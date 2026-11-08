//! MAC address spoofing / randomisation via iproute2, with save & restore.

use std::path::PathBuf;
use std::process::Command;

use rand::Rng;

use crate::net::err;

fn state_file(iface: &str) -> PathBuf {
    std::env::temp_dir().join(format!("arp-spoofer-{iface}.mac"))
}

fn ip(args: &[&str]) -> std::io::Result<()> {
    let status = Command::new("ip").args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(err(&format!("`ip {}` failed", args.join(" "))))
    }
}

/// Read the interface's current hardware address.
pub fn current_mac(iface: &str) -> Option<String> {
    let out = Command::new("ip")
        .args(["link", "show", "dev", iface])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let idx = text.find("link/ether ")? + "link/ether ".len();
    text[idx..].split_whitespace().next().map(str::to_string)
}

fn set_mac(iface: &str, mac: &str) -> std::io::Result<()> {
    ip(&["link", "set", "dev", iface, "down"])?;
    ip(&["link", "set", "dev", iface, "address", mac])?;
    ip(&["link", "set", "dev", iface, "up"])?;
    Ok(())
}

/// Random locally-administered unicast MAC.
fn random_mac() -> String {
    let mut r = rand::thread_rng();
    let first = (r.gen::<u8>() & 0xFC) | 0x02; // LAA + unicast
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        first,
        r.gen::<u8>(),
        r.gen::<u8>(),
        r.gen::<u8>(),
        r.gen::<u8>(),
        r.gen::<u8>()
    )
}

pub fn run(iface: &str, set: Option<String>, random: bool, restore: bool) -> std::io::Result<()> {
    let state = state_file(iface);

    if restore {
        let orig = std::fs::read_to_string(&state)
            .map_err(|_| err("no saved MAC to restore (nothing was spoofed on this interface)"))?;
        let orig = orig.trim();
        set_mac(iface, orig)?;
        let _ = std::fs::remove_file(&state);
        println!("restored {iface} -> {orig}");
        return Ok(());
    }

    let new_mac = match (random, set) {
        (true, _) => random_mac(),
        (false, Some(m)) => m,
        (false, None) => {
            return Err(err("specify --random, --set <MAC>, or --restore"));
        }
    };

    // Preserve the original MAC once, so --restore always works.
    if !state.exists() {
        if let Some(orig) = current_mac(iface) {
            let _ = std::fs::write(&state, orig);
        }
    }

    set_mac(iface, &new_mac)?;
    println!("set {iface} -> {new_mac}");
    println!("(restore with: arp-spoofer mac -i {iface} --restore)");
    Ok(())
}
