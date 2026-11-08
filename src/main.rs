//! arp-spoofer — LAN MITM & spoofing toolkit for authorised network assessments.
//!
//! Subcommands: scan (ARP discovery), arp (ARP-spoof MITM), mac (MAC spoof),
//! respond (LLMNR/NBT-NS/mDNS poisoning). All active modes clean up after
//! themselves — ARP caches are healed on exit and MAC changes are restorable.
//!
//! Only run this against networks you own or are explicitly authorised to test.

mod arp;
mod capture;
mod detect;
mod dhcp;
mod dnsspoof;
mod log;
mod mac;
mod mitm6;
mod net;
mod ntlm;
mod responder;
mod scan;
mod sniff;

use log::Logger;

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use pnet::datalink::NetworkInterface;

use net::find_interface;

#[derive(Parser)]
#[command(
    name = "arp-spoofer",
    version,
    about = "LAN MITM & spoofing toolkit for authorised network assessments"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Discover live hosts on the interface's subnet via ARP
    Scan {
        #[arg(short, long)]
        iface: String,
        /// Emit results as JSON
        #[arg(long)]
        json: bool,
    },
    /// ARP-spoof a MITM between a target and the gateway (restores on exit)
    Arp {
        #[arg(short, long)]
        iface: String,
        /// Target host IP (omit with --all)
        #[arg(short, long)]
        target: Option<Ipv4Addr>,
        #[arg(short, long)]
        gateway: Ipv4Addr,
        /// MITM every discovered host against the gateway
        #[arg(long)]
        all: bool,
        /// Seconds between poison rounds
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },
    /// Spoof, randomise or restore the interface MAC address
    Mac {
        #[arg(short, long)]
        iface: String,
        /// Set a specific MAC (AA:BB:CC:DD:EE:FF)
        #[arg(long)]
        set: Option<String>,
        /// Use a random locally-administered MAC
        #[arg(long)]
        random: bool,
        /// Restore the MAC saved before the last spoof
        #[arg(long)]
        restore: bool,
    },
    /// Poison LLMNR / NBT-NS / mDNS name resolution (or --analyze passively)
    Respond {
        #[arg(short, long)]
        iface: String,
        /// Observe queries without answering them
        #[arg(long)]
        analyze: bool,
    },
    /// Sniff cleartext credentials (HTTP Basic/form, FTP) from passing traffic
    Sniff {
        #[arg(short, long)]
        iface: String,
        /// Append captured credentials as JSONL to this file
        #[arg(long)]
        log: Option<String>,
    },
    /// Defensive mode: watch for ARP poisoning, rogue DHCP and name responders
    Detect {
        #[arg(short, long)]
        iface: String,
        /// Append alerts as JSONL to this file
        #[arg(long)]
        log: Option<String>,
    },
    /// Capture NetNTLM hashes via HTTP/SMB listeners (pair with respond)
    Capture {
        /// Append captured hashes as JSONL to this file
        #[arg(long)]
        log: Option<String>,
    },
    /// Forge DNS replies for passing queries (be MITM first via `arp`)
    Dnsspoof {
        #[arg(short, long)]
        iface: String,
        /// IP to answer with (default: this interface's IP)
        #[arg(long)]
        spoof: Option<Ipv4Addr>,
        /// Only spoof names containing one of these substrings
        #[arg(long)]
        domain: Vec<String>,
        #[arg(long)]
        log: Option<String>,
    },
    /// Rogue DHCP server, or --starve the real server's pool
    Dhcp {
        #[arg(short, long)]
        iface: String,
        /// Flood DISCOVERs to exhaust the pool instead of serving leases
        #[arg(long)]
        starve: bool,
        #[arg(long)]
        log: Option<String>,
    },
    /// EXPERIMENTAL: IPv6 DNS takeover via rogue RA + DHCPv6
    Mitm6 {
        #[arg(short, long)]
        iface: String,
        #[arg(long)]
        log: Option<String>,
    },
}

fn banner() {
    eprintln!(
        "arp-spoofer — authorised use only.\n\
         Run only against networks you own or are explicitly permitted to test.\n"
    );
}

fn main() {
    let cli = Cli::parse();
    banner();

    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        let _ = ctrlc::set_handler(move || r.store(false, Ordering::SeqCst));
    }

    let result = match cli.cmd {
        Cmd::Scan { iface, json } => with_iface(&iface, |i| scan::run(i, json)),
        Cmd::Arp {
            iface,
            target,
            gateway,
            all,
            interval,
        } => with_iface(&iface, |i| {
            if all {
                arp::run_subnet(i, gateway, interval, running.clone())
            } else if let Some(target) = target {
                arp::run(i, target, gateway, interval, running.clone())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "specify --target <IP> or --all",
                ))
            }
        }),
        Cmd::Mac {
            iface,
            set,
            random,
            restore,
        } => mac::run(&iface, set, random, restore),
        Cmd::Respond { iface, analyze } => {
            with_iface(&iface, |i| responder::run(i, analyze, running.clone()))
        }
        Cmd::Sniff { iface, log } => with_iface(&iface, |i| {
            sniff::run(i, Logger::new(log.as_deref()), running.clone())
        }),
        Cmd::Detect { iface, log } => with_iface(&iface, |i| {
            detect::run(i, Logger::new(log.as_deref()), running.clone())
        }),
        Cmd::Capture { log } => capture::run(log, running.clone()),
        Cmd::Dnsspoof {
            iface,
            spoof,
            domain,
            log,
        } => with_iface(&iface, |i| {
            dnsspoof::run(i, spoof, domain, Logger::new(log.as_deref()), running.clone())
        }),
        Cmd::Dhcp { iface, starve, log } => with_iface(&iface, |i| {
            if starve {
                dhcp::starve(i, running.clone())
            } else {
                dhcp::rogue(i, Logger::new(log.as_deref()), running.clone())
            }
        }),
        Cmd::Mitm6 { iface, log } => with_iface(&iface, |i| {
            mitm6::run(i, Logger::new(log.as_deref()), running.clone())
        }),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn with_iface<F>(name: &str, f: F) -> std::io::Result<()>
where
    F: FnOnce(&NetworkInterface) -> std::io::Result<()>,
{
    let iface = find_interface(name).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("interface '{name}' not found"),
        )
    })?;
    f(&iface)
}
