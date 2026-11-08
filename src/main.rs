//! arp-spoofer — LAN MITM & spoofing toolkit for authorised network assessments.
//!
//! Subcommands: scan (ARP discovery), arp (ARP-spoof MITM), mac (MAC spoof),
//! respond (LLMNR/NBT-NS/mDNS poisoning). All active modes clean up after
//! themselves — ARP caches are healed on exit and MAC changes are restorable.
//!
//! Only run this against networks you own or are explicitly authorised to test.

mod arp;
mod mac;
mod net;
mod responder;
mod scan;

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
    },
    /// ARP-spoof a MITM between a target and the gateway (restores on exit)
    Arp {
        #[arg(short, long)]
        iface: String,
        #[arg(short, long)]
        target: Ipv4Addr,
        #[arg(short, long)]
        gateway: Ipv4Addr,
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
        Cmd::Scan { iface } => with_iface(&iface, scan::run),
        Cmd::Arp {
            iface,
            target,
            gateway,
            interval,
        } => with_iface(&iface, |i| {
            arp::run(i, target, gateway, interval, running.clone())
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
