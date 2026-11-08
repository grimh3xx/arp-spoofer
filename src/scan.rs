//! ARP host discovery: sweep the interface's subnet and list responders.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;

use crate::net::{build_arp, err, iface_ipv4, iface_net, open_channel};

pub fn run(iface: &NetworkInterface) -> std::io::Result<()> {
    let src_mac = iface.mac.ok_or_else(|| err("interface has no MAC"))?;
    let src_ip = iface_ipv4(iface).ok_or_else(|| err("interface has no IPv4"))?;
    let net = iface_net(iface).ok_or_else(|| err("interface has no IPv4 network"))?;

    let start = u32::from(net.network());
    let end = u32::from(net.broadcast());
    if end.saturating_sub(start) > 65_536 {
        return Err(err("subnet larger than /16 — narrow the scan"));
    }

    let hosts = end.saturating_sub(start).saturating_sub(1);
    let (mut tx, mut rx) = open_channel(iface, Some(Duration::from_millis(500)))?;
    println!("scanning {net} on {} ({hosts} hosts)...", iface.name);

    for host in (start + 1)..end {
        let ip = Ipv4Addr::from(host);
        let frame = build_arp(
            src_mac,
            src_ip,
            MacAddr::broadcast(),
            MacAddr::zero(),
            ip,
            ArpOperations::Request,
        );
        tx.send_to(&frame, None);
    }

    let mut found: BTreeMap<u32, MacAddr> = BTreeMap::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Ok(frame) = rx.next() {
            if let Some(eth) = EthernetPacket::new(frame) {
                if eth.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp) = ArpPacket::new(eth.payload()) {
                        if arp.get_operation() == ArpOperations::Reply {
                            found.insert(
                                u32::from(arp.get_sender_proto_addr()),
                                arp.get_sender_hw_addr(),
                            );
                        }
                    }
                }
            }
        }
    }

    println!("\n{:<16}  MAC", "IP");
    println!("{}", "-".repeat(36));
    for (ip, mac) in &found {
        println!("{:<16}  {}", Ipv4Addr::from(*ip), mac);
    }
    println!("\n{} host(s) up.", found.len());
    Ok(())
}
