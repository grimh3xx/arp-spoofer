//! Defensive mode: passively watch the wire for the very techniques this tool
//! can perform — ARP cache poisoning, duplicate gateway MACs, rogue DHCP
//! servers, and active LLMNR/NBT-NS responders.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use crate::log::Logger;
use crate::net::open_channel;

pub fn run(iface: &NetworkInterface, logger: Logger, running: Arc<AtomicBool>) -> std::io::Result<()> {
    let (_tx, mut rx) = open_channel(iface, Some(Duration::from_secs(1)))?;
    println!("watching {} for spoofing activity (Ctrl+C to stop)...\n", iface.name);

    let mut arp_map: HashMap<Ipv4Addr, MacAddr> = HashMap::new();
    let mut dhcp_servers: HashMap<Ipv4Addr, MacAddr> = HashMap::new();
    let mut responders: HashMap<Ipv4Addr, u16> = HashMap::new();

    while running.load(Ordering::SeqCst) {
        let Ok(frame) = rx.next() else { continue };
        let Some(eth) = EthernetPacket::new(frame) else { continue };
        match eth.get_ethertype() {
            EtherTypes::Arp => {
                if let Some(arp) = ArpPacket::new(eth.payload()) {
                    if arp.get_operation() == ArpOperations::Reply {
                        let ip = arp.get_sender_proto_addr();
                        let mac = arp.get_sender_hw_addr();
                        if let Some(prev) = arp_map.insert(ip, mac) {
                            if prev != mac {
                                alert(
                                    &logger,
                                    "arp-poison",
                                    &format!(
                                        "{ip} changed MAC {prev} -> {mac} (possible ARP spoofing)"
                                    ),
                                );
                            }
                        }
                    }
                }
            }
            EtherTypes::Ipv4 => {
                let Some(ip) = Ipv4Packet::new(eth.payload()) else { continue };
                if ip.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
                    continue;
                }
                let Some(udp) = UdpPacket::new(ip.payload()) else { continue };
                let (sport, src) = (udp.get_source(), ip.get_source());
                match sport {
                    // DHCP server -> client
                    67 => {
                        if dhcp_servers.insert(src, eth.get_source()).is_none() {
                            alert(
                                &logger,
                                "dhcp-server",
                                &format!("DHCP server seen at {src} ({}) — verify it is authorised", eth.get_source()),
                            );
                        }
                    }
                    // LLMNR / NBT-NS responses
                    5355 | 137 => {
                        let n = responders.entry(src).or_insert(0);
                        *n += 1;
                        if *n == 3 {
                            alert(
                                &logger,
                                "name-responder",
                                &format!("{src} is answering LLMNR/NBT-NS queries (possible poisoner)"),
                            );
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn alert(logger: &Logger, kind: &str, msg: &str) {
    println!("[!] {msg}");
    logger.event(kind, "", serde_json::json!({ "message": msg }));
}
