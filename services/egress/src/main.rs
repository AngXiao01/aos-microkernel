//! Egress gateway (SPEC §B4, §B7, BS8).
//!
//! Holds the only send capability on the netstack's outbound endpoint. On boot it refuses a
//! swapped payload (BS8) and opens a TLS 1.3 session to https://example.com, checking the
//! certificate chain against the pinned SSL.com TLS ECC Root CA 2022 public key. TLS is
//! embedded-tls: rustls's RustCrypto provider still draws randomness from `OsRng`, which
//! this target does not have (see DECISIONS.md).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use aos_confirm::{ApprovalRequest, Decision, Item, Kind, Verified};
use aos_egress::{Authorization, Gate, GateError, Intent, Transport};
use aos_rt::abi::{MsgInfo, method};
use aos_rt::cap::map;
use aos_rt::println;
use aos_rt::proto;
use aos_rt::{call, ipc_buffer};
use aos_types::{Hash256, Timestamp, Ulid};
use embedded_io::{ErrorType, Read, Write};
use embedded_tls::blocking::{Aes128GcmSha256, CertificateRef, TlsConfig, TlsConnection, TlsContext};
use embedded_tls::{TlsError, TlsVerifier};
use linked_list_allocator::LockedHeap;
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;

aos_rt::entry!(main);

#[global_allocator]
static ALLOC: LockedHeap = LockedHeap::empty();

const OUTBOUND: u64 = 1;
const SPACE: u64 = 4;
const MEM: u64 = 6;
const FRAME: u64 = 20;
const HEAP: u64 = 160;
const HEAP_PAGES: u64 = 40;
const FRAME_VA: u64 = 0x0000_5000_0001_0000;
const HEAP_VA: u64 = 0x0000_5000_0040_0000;

/// Guest has no wall clock. This is 2026-10-31, inside the example.com certificate's life.
const NOW: u64 = 1_793_432_547;
const DNS: u32 = 0x0A00_0203;
/// SHA-256 of `sslcom-ecc-root.der` (SSL.com TLS ECC Root CA 2022). The leaf chain up to
/// this key is ECDSA; the root's own signature is RSA from AAA Certificate Services, which
/// we do not re-check. Pinning this public key rejects a proxy CA.
const ROOT_SHA256: &str = "ba06d3d3e348fce7478cc84b422d0e638e9e221ef1a0b53adc14cc70e04b8ab8";

const ROOT: &[u8] = include_bytes!("../sslcom-ecc-root.der");

fn alloc_frames(slot: u64, count: u64) -> u64 {
    ipc_buffer().recv_slot = slot;
    let r = call(MEM, MsgInfo::new(proto::memory::ALLOC_FRAMES, 1), [count, 0, 0, 0], 0);
    if r.is_ok() { r.info.caps() as u64 } else { 0 }
}

struct Stack;

impl Stack {
    fn call(&self, label: u64, words: [u64; 4], bytes: &[u8]) -> (u64, Vec<u8>) {
        let n = bytes.len().min(4000);
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), FRAME_VA as *mut u8, n) };
        ipc_buffer().caps[0] = FRAME;
        let r = call(OUTBOUND, MsgInfo::new(label, 4).with_caps(1), words, 0);
        let got = r.words[0] as usize;
        let mut out = Vec::new();
        if r.is_ok() && got > 0 && got <= 4000 && label != proto::stack::CONNECT && label != proto::stack::SEND {
            out.resize(got, 0);
            unsafe { core::ptr::copy_nonoverlapping(FRAME_VA as *const u8, out.as_mut_ptr(), got) };
        }
        let status = if r.is_ok() { r.words[0] } else { 0xffff };
        (status, out)
    }

    fn connect(&self, ip: [u8; 4], port: u16) -> bool {
        let addr = u32::from_be_bytes(ip) as u64;
        let (status, _) = self.call(proto::stack::CONNECT, [addr, u64::from(port), 0, 0], &[]);
        status == 0
    }

    fn send_all(&self, data: &[u8]) -> bool {
        let mut off = 0;
        while off < data.len() {
            let n = (data.len() - off).min(1400);
            let (status, _) = self.call(proto::stack::SEND, [1, n as u64, 0, 0], &data[off..off + n]);
            if status != 0 {
                return false;
            }
            off += n;
        }
        true
    }

    fn udp(&self, ip: u32, port: u16, query: &[u8]) -> Vec<u8> {
        let (_, bytes) = self.call(proto::stack::UDP, [u64::from(ip), u64::from(port), query.len() as u64, 0], query);
        bytes
    }
}

struct Tcp {
    stack: Stack,
    /// Bytes pulled from TCP but not yet consumed. embedded-tls reads a 5-byte record
    /// header first; dropping the rest of that segment desynchronizes the handshake.
    pending: Vec<u8>,
}

#[derive(Debug)]
struct IoErr;

impl core::fmt::Display for IoErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("io")
    }
}

impl core::error::Error for IoErr {}

impl embedded_io::Error for IoErr {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

impl ErrorType for Tcp {
    type Error = IoErr;
}

impl Read for Tcp {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoErr> {
        if self.pending.is_empty() {
            let (_, bytes) = self.stack.call(proto::stack::RECV, [1, 0, 0, 0], &[]);
            if bytes.is_empty() {
                return Err(IoErr);
            }
            self.pending = bytes;
        }
        let n = buf.len().min(self.pending.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
}

impl Write for Tcp {
    fn write(&mut self, buf: &[u8]) -> Result<usize, IoErr> {
        if self.stack.send_all(buf) { Ok(buf.len()) } else { Err(IoErr) }
    }

    fn flush(&mut self) -> Result<(), IoErr> {
        Ok(())
    }
}

struct CounterRng(u64);

impl RngCore for CounterRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(0x5851_F42D_4C95_7F2D).wrapping_add(0x1405_7B7E_F767_814F);
        self.0 ^= aos_rt::counter();
        self.0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let n = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&n[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for CounterRng {}

struct Provider {
    rng: CounterRng,
    verifier: PubVerify,
}

struct PubVerify {
    transcript: Option<sha2::Sha256>,
    leaf: Vec<u8>,
}

impl embedded_tls::CryptoProvider for Provider {
    type CipherSuite = Aes128GcmSha256;
    type Signature = p256::ecdsa::DerSignature;

    fn rng(&mut self) -> impl rand_core::CryptoRngCore {
        &mut self.rng
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Self::CipherSuite>, TlsError> {
        Ok(&mut self.verifier)
    }
}

impl TlsVerifier<Aes128GcmSha256> for PubVerify {
    fn set_hostname_verification(&mut self, _hostname: &str) -> Result<(), TlsError> {
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &<Aes128GcmSha256 as embedded_tls::TlsCipherSuite>::Hash,
        cert: CertificateRef,
    ) -> Result<(), TlsError> {
        use embedded_tls::blocking::CertificateEntryRef;
        let mut ders = Vec::new();
        for entry in &cert.entries {
            if let CertificateEntryRef::X509(der) = entry {
                ders.push(*der);
            }
        }
        if !chain_to_pinned_root(&ders) {
            return Err(TlsError::InvalidCertificate);
        }
        self.leaf = ders[0].to_vec();
        self.transcript = Some(transcript.clone());
        Ok(())
    }

    fn verify_signature(&mut self, verify: embedded_tls::CertificateVerifyRef) -> Result<(), TlsError> {
        let Some(hash) = self.transcript.take() else { return Err(TlsError::InvalidSignature) };
        let mut msg = Vec::new();
        msg.resize(64, 0x20);
        msg.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
        msg.extend_from_slice(&hash.finalize());
        let leaf = parse_cert(&self.leaf).ok_or(TlsError::InvalidCertificate)?;
        if !verify_ecdsa(leaf.curve, leaf.point, &msg, verify.signature) {
            return Err(TlsError::InvalidSignature);
        }
        Ok(())
    }
}

struct Parsed<'a> {
    tbs: &'a [u8],
    point: &'a [u8],
    curve: u16,
    sig: &'a [u8],
}

fn parse_cert(der: &[u8]) -> Option<Parsed<'_>> {
    let (tag, body, _) = tlv(der)?;
    if tag != 0x30 {
        return None;
    }
    let (tbs_tag, _, after_tbs) = tlv(body)?;
    if tbs_tag != 0x30 {
        return None;
    }
    let tbs_len = body.len() - after_tbs.len();
    let tbs = &body[..tbs_len];
    let (_, _, after_alg) = tlv(after_tbs)?;
    let (sig_tag, sig_body, _) = tlv(after_alg)?;
    if sig_tag != 0x03 || sig_body.first() != Some(&0) {
        return None;
    }
    let sig = &sig_body[1..];
    let (_, tbs_body, _) = tlv(tbs)?;
    let point = spki_point(tbs_body)?;
    let curve = if point.len() == 65 {
        256
    } else if point.len() == 97 {
        384
    } else {
        return None;
    };
    Some(Parsed { tbs, point, curve, sig })
}

fn spki_point(tbs_body: &[u8]) -> Option<&[u8]> {
    let mut rest = tbs_body;
    // version [0] EXPLICIT is optional
    if rest.first() == Some(&0xa0) {
        let (_, _, next) = tlv(rest)?;
        rest = next;
    }
    for _ in 0..5 {
        let (_, _, next) = tlv(rest)?;
        rest = next;
    }
    let (tag, spki, _) = tlv(rest)?;
    if tag != 0x30 {
        return None;
    }
    let (_, _, after_alg) = tlv(spki)?;
    let (bit_tag, bit_body, _) = tlv(after_alg)?;
    if bit_tag != 0x03 || bit_body.first() != Some(&0) {
        return None;
    }
    Some(&bit_body[1..])
}

fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (tag, rest) = input.split_first()?;
    let (len, rest) = der_len(rest)?;
    if rest.len() < len {
        return None;
    }
    Some((*tag, &rest[..len], &rest[len..]))
}

fn der_len(input: &[u8]) -> Option<(usize, &[u8])> {
    let (first, rest) = input.split_first()?;
    if *first < 0x80 {
        return Some((*first as usize, rest));
    }
    let n = (*first & 0x7f) as usize;
    if n == 0 || n > 3 || rest.len() < n {
        return None;
    }
    let mut len = 0usize;
    for b in &rest[..n] {
        len = (len << 8) | *b as usize;
    }
    Some((len, &rest[n..]))
}

fn verify_ecdsa(curve: u16, point: &[u8], message: &[u8], sig: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    if curve == 256 {
        let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(point) else { return false };
        let Ok(sig) = p256::ecdsa::Signature::from_der(sig) else { return false };
        key.verify(message, &sig).is_ok()
    } else if curve == 384 {
        let Ok(key) = p384::ecdsa::VerifyingKey::from_sec1_bytes(point) else { return false };
        let Ok(sig) = p384::ecdsa::Signature::from_der(sig) else { return false };
        key.verify(message, &sig).is_ok()
    } else {
        false
    }
}

fn chain_to_pinned_root(ders: &[&[u8]]) -> bool {
    if ders.is_empty() || !contains_exact_name(ders[0], b"example.com") {
        return false;
    }
    let Some(root) = parse_cert(ROOT) else { return false };
    let mut current = match parse_cert(ders[0]) {
        Some(c) => c,
        None => return false,
    };
    for _ in 0..6 {
        if current.point == root.point {
            return true;
        }
        let mut advanced = false;
        for der in ders.iter().copied().chain(core::iter::once(ROOT)) {
            let Some(parent) = parse_cert(der) else { continue };
            if parent.point == current.point {
                continue;
            }
            if verify_ecdsa(parent.curve, parent.point, current.tbs, current.sig) {
                current = parent;
                advanced = true;
                break;
            }
        }
        if !advanced {
            return false;
        }
    }
    false
}

fn contains_exact_name(der: &[u8], name: &[u8]) -> bool {
    if name.len() > 127 {
        return false;
    }
    for tag in [0x0cu8, 0x13, 0x16] {
        let mut pattern = Vec::with_capacity(2 + name.len());
        pattern.push(tag);
        pattern.push(name.len() as u8);
        pattern.extend_from_slice(name);
        if der.windows(pattern.len()).any(|w| w == pattern.as_slice()) {
            return true;
        }
    }
    false
}

fn dns_query(name: &str) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&0xA05Au16.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

fn skip_name(msg: &[u8], i: &mut usize) -> bool {
    let mut hops = 0;
    while *i < msg.len() && hops < 64 {
        let len = msg[*i] as usize;
        if len == 0 {
            *i += 1;
            return true;
        }
        if len & 0xc0 == 0xc0 {
            *i += 2;
            return true;
        }
        *i += 1 + len;
        hops += 1;
    }
    false
}

fn parse_a(msg: &[u8]) -> Option<[u8; 4]> {
    if msg.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut i = 12;
    for _ in 0..qd {
        if !skip_name(msg, &mut i) || i + 4 > msg.len() {
            return None;
        }
        i += 4;
    }
    for _ in 0..an {
        if !skip_name(msg, &mut i) || i + 10 > msg.len() {
            return None;
        }
        let typ = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let rdlen = u16::from_be_bytes([msg[i + 8], msg[i + 9]]) as usize;
        i += 10;
        if i + rdlen > msg.len() {
            return None;
        }
        if typ == 1 && rdlen == 4 {
            return Some([msg[i], msg[i + 1], msg[i + 2], msg[i + 3]]);
        }
        i += rdlen;
    }
    None
}

fn handshake(stack: &Stack) -> Result<(), &'static str> {
    let response = stack.udp(DNS, 53, &dns_query("example.com"));
    let ip = match parse_a(&response) {
        Some(ip) => ip,
        None => {
            println!("egress: dns failed ({} bytes)", response.len());
            return Err("dns");
        }
    };
    println!("egress: example.com is {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    if !stack.connect(ip, 443) {
        return Err("tcp");
    }
    println!("egress: tcp connected");
    let mut read_buf = alloc::vec![0u8; 16384];
    let mut write_buf = alloc::vec![0u8; 4096];
    let config = TlsConfig::new().with_server_name("example.com");
    let provider =
        Provider { rng: CounterRng(0xA05A_11CE), verifier: PubVerify { transcript: None, leaf: Vec::new() } };
    let mut tls = TlsConnection::<_, Aes128GcmSha256>::new(
        Tcp { stack: Stack, pending: Vec::new() },
        &mut read_buf,
        &mut write_buf,
    );
    if let Err(e) = tls.open(TlsContext::new(&config, provider)) {
        println!("egress: tls error {e:?}");
        return Err("handshake");
    }
    println!("egress: TLS handshake ok (example.com, root {ROOT_SHA256})");
    Ok(())
}

struct Rec(bool);

impl Transport for Rec {
    fn send(&mut self, _: &str, _: &str, _: &[u8]) -> Result<Vec<u8>, String> {
        self.0 = true;
        Ok(Vec::new())
    }
}

fn bs8() {
    let approved = b"approved-payload";
    let hash = Hash256::digest(approved);
    let intent = Intent {
        id: Ulid::from_u128(8),
        channel: "deliver:test".into(),
        target: "example.com:443".into(),
        payload_hash: hash,
    };
    let request = ApprovalRequest {
        request_id: Ulid::from_u128(80),
        created_at: Timestamp(NOW * 1000),
        expires_at: Timestamp((NOW + 3600) * 1000),
        nonce: [7; 16],
        kind: Kind::Egress,
        summary: Vec::new(),
        items: alloc::vec![Item {
            channel: intent.channel.clone(),
            target: intent.target.clone(),
            payload_hash: hash,
            cost_fen: 0,
            external_reversibility: "irreversible".into(),
            tainted: false,
        }],
        branch: "main".into(),
        diff_hash: Hash256([0; 32]),
    };
    let verified = Verified { request, decision: Decision::Approve };
    let mut gate = Gate::new(Rec(false));
    let err = gate.execute(&intent, b"replaced-payload", Authorization::Approval(&verified));
    if err == Err(GateError::PayloadMismatch) && !gate.transport().0 {
        println!("egress: BS8 payload mismatch refused");
    } else {
        println!("egress: BS8 unexpected {err:?}");
    }
}

fn main(_: u64, _: u64) -> u64 {
    let mut done = 0u64;
    while done < HEAP_PAGES {
        let got = alloc_frames(HEAP + done, (HEAP_PAGES - done).min(3));
        if got == 0 {
            println!("egress: no heap");
            return 1;
        }
        for i in 0..got {
            let _ = map(SPACE, HEAP + done + i, HEAP_VA + (done + i) * 4096, method::WRITE);
        }
        done += got;
    }
    unsafe { ALLOC.lock().init(HEAP_VA as *mut u8, (HEAP_PAGES * 4096) as usize) };
    if alloc_frames(FRAME, 1) != 1 || map(SPACE, FRAME, FRAME_VA, method::WRITE).is_err() {
        println!("egress: no frame");
        return 1;
    }
    bs8();
    let stack = Stack;
    match handshake(&stack) {
        Ok(()) => 0,
        Err(e) => {
            println!("egress: TLS handshake failed: {e}");
            1
        }
    }
}
