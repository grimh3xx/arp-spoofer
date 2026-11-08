//! Shared datalink helpers: interface lookup, ARP frame construction, and
//! MAC resolution.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::datalink::{
    self, Channel, Config, DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface,
};
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use pnet::packet::arp::{
    ArpHardwareTypes, ArpOperation, ArpOperations, ArpPacket, MutableArpPacket,
};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;

pub fn err(msg: &str) -> std::io::Error {
    std::io::Error::other(msg.to_string())
}

pub fn find_interface(name: &str) -> Option<NetworkInterface> {
    datalink::interfaces().into_iter().find(|i| i.name == name)
}

pub fn iface_ipv4(iface: &NetworkInterface) -> Option<Ipv4Addr> {
    iface.ips.iter().find_map(|ip| match ip {
        IpNetwork::V4(v4) => Some(v4.ip()),
        _ => None,
    })
}

pub fn iface_net(iface: &NetworkInterface) -> Option<Ipv4Network> {
    iface.ips.iter().find_map(|ip| match ip {
        IpNetwork::V4(v4) => Some(*v4),
        _ => None,
    })
}

pub fn open_channel(
    iface: &NetworkInterface,
    read_timeout: Option<Duration>,
) -> std::io::Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    let cfg = Config {
        read_timeout,
        ..Default::default()
    };
    match datalink::channel(iface, cfg)? {
        Channel::Ethernet(tx, rx) => Ok((tx, rx)),
        _ => Err(err("unsupported channel type")),
    }
}

/// Build a 42-byte Ethernet+ARP frame.
pub fn build_arp(
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    eth_dst: MacAddr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
    op: ArpOperation,
) -> [u8; 42] {
    let mut buf = [0u8; 42];
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..14]).unwrap();
        eth.set_destination(eth_dst);
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Arp);
    }
    {
        let mut arp = MutableArpPacket::new(&mut buf[14..]).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(op);
        arp.set_sender_hw_addr(src_mac);
        arp.set_sender_proto_addr(src_ip);
        arp.set_target_hw_addr(target_mac);
        arp.set_target_proto_addr(target_ip);
    }
    buf
}

/// Resolve an IPv4 address to its MAC via a blocking ARP request.
pub fn resolve_mac(
    iface: &NetworkInterface,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    timeout: Duration,
) -> Option<MacAddr> {
    let (mut tx, mut rx) = open_channel(iface, Some(Duration::from_millis(500))).ok()?;
    let req = build_arp(
        src_mac,
        src_ip,
        MacAddr::broadcast(),
        MacAddr::zero(),
        target_ip,
        ArpOperations::Request,
    );
    tx.send_to(&req, None);
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match rx.next() {
            Ok(frame) => {
                if let Some(eth) = EthernetPacket::new(frame) {
                    if eth.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(eth.payload()) {
                            if arp.get_operation() == ArpOperations::Reply
                                && arp.get_sender_proto_addr() == target_ip
                            {
                                return Some(arp.get_sender_hw_addr());
                            }
                        }
                    }
                }
            }
            Err(_) => {
                tx.send_to(&req, None);
            }
        }
    }
    None
}
