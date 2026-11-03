//! IPv4 netstack on virtio-net (smoltcp). QEMU user-net gives the guest 10.0.2.15/24
//! via the gateway 10.0.2.2; DNS for the egress gateway is the slirp resolver 10.0.2.3.
//!
//! Slot 1: receive end of the outbound endpoint. Slot 4: address space. Slot 5: net driver.
//! Slot 6: memory server. Slot 7: receive end of the inbound endpoint.
//!
//! The send end of the outbound endpoint (badge [`proto::stack::BADGE_OUTBOUND`]) is only
//! given to the egress gateway. View holds the inbound send end and is refused CONNECT/UDP.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use aos_rt::abi::{MsgInfo, method};
use aos_rt::cap::{map, phys};
use aos_rt::println;
use aos_rt::proto;
use aos_rt::{call, ipc_buffer, recv, reply};
use linked_list_allocator::LockedHeap;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, RxToken, TxToken};
use smoltcp::socket::tcp::{self, Socket as TcpSocket};
use smoltcp::socket::udp::{self, Socket as UdpSocket};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

aos_rt::entry!(main);

#[global_allocator]
static ALLOC: LockedHeap = LockedHeap::empty();

const OUT_EP: u64 = 1;
const SPACE: u64 = 4;
const NIC: u64 = 5;
const MEM: u64 = 6;
const IN_EP: u64 = 7;
const FRAME: u64 = 20;
/// Empty slot that receives a client's lent frame. Must not be `FRAME`.
const LENT: u64 = 21;
const HEAP: u64 = 128;
const HEAP_PAGES: u64 = 32;
const FRAME_VA: u64 = 0x0000_5000_0001_0000;
const LENT_VA: u64 = 0x0000_5000_0001_1000;
const HEAP_VA: u64 = 0x0000_5000_0020_0000;

const LOCAL_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 15);
const GATEWAY: Ipv4Address = Ipv4Address::new(10, 0, 2, 2);

fn now() -> Instant {
    let hz = aos_rt::counter_frequency().max(1);
    Instant::from_micros((aos_rt::counter() / (hz / 1_000_000).max(1)) as i64)
}

fn alloc_frames(slot: u64, count: u64) -> u64 {
    ipc_buffer().recv_slot = slot;
    let r = call(MEM, MsgInfo::new(proto::memory::ALLOC_FRAMES, 1), [count, 0, 0, 0], 0);
    if r.is_ok() { r.info.caps() as u64 } else { 0 }
}

struct Nic;

impl Nic {
    fn mac() -> [u8; 6] {
        let r = call(NIC, MsgInfo::new(proto::net::MAC, 0), [0; 4], 0);
        let lo = r.words[0].to_le_bytes();
        let hi = r.words[1].to_le_bytes();
        [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1]]
    }

    fn tx(frame: &[u8]) {
        unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), FRAME_VA as *mut u8, frame.len()) };
        ipc_buffer().caps[0] = FRAME;
        let _ = call(NIC, MsgInfo::new(proto::net::TX, 1).with_caps(1), [frame.len() as u64, 0, 0, 0], 0);
    }

    fn rx() -> Option<Vec<u8>> {
        ipc_buffer().caps[0] = FRAME;
        let r = call(NIC, MsgInfo::new(proto::net::RX, 0).with_caps(1), [0; 4], 0);
        let n = r.words[0] as usize;
        if !r.is_ok() || n == 0 {
            return None;
        }
        let mut buf = alloc::vec![0u8; n];
        unsafe { core::ptr::copy_nonoverlapping(FRAME_VA as *const u8, buf.as_mut_ptr(), n) };
        Some(buf)
    }
}

struct Phy {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct RxTok(Vec<u8>);
struct TxTok(*mut Phy);

impl RxToken for RxTok {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

impl TxToken for TxTok {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = alloc::vec![0u8; len];
        let result = f(&mut buf);
        unsafe { (*self.0).tx.push_back(buf) };
        result
    }
}

impl Device for Phy {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.medium = smoltcp::phy::Medium::Ethernet;
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((RxTok(pkt), TxTok(self as *mut Phy)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTok(self as *mut Phy))
    }
}

fn poll(iface: &mut Interface, phy: &mut Phy, sockets: &mut SocketSet<'_>) {
    while let Some(pkt) = Nic::rx() {
        phy.rx.push_back(pkt);
    }
    let _ = iface.poll(now(), phy, sockets);
    while let Some(pkt) = phy.tx.pop_front() {
        Nic::tx(&pkt);
    }
}

fn wait_connect(
    iface: &mut Interface,
    phy: &mut Phy,
    sockets: &mut SocketSet<'_>,
    tcp: smoltcp::iface::SocketHandle,
) -> bool {
    for attempt in 0..2000 {
        poll(iface, phy, sockets);
        let sock = sockets.get_mut::<TcpSocket>(tcp);
        if sock.can_send() {
            return true;
        }
        if matches!(sock.state(), tcp::State::Closed | tcp::State::TimeWait) && attempt > 10 {
            return false;
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn handle(
    outbound: bool,
    label: u64,
    words: [u64; 4],
    iface: &mut Interface,
    phy: &mut Phy,
    sockets: &mut SocketSet<'_>,
    tcp_h: smoltcp::iface::SocketHandle,
    udp_h: smoltcp::iface::SocketHandle,
    local_port: &mut u16,
) {
    if !outbound && matches!(label, proto::stack::CONNECT | proto::stack::UDP) {
        reply(MsgInfo::new(proto::stack::DENIED, 1), [proto::stack::DENIED, 0, 0, 0]);
        println!("netstack: inbound endpoint refused an outbound call");
        return;
    }
    match label {
        proto::stack::CONNECT => {
            let ip = Ipv4Address::from_bytes(&(words[0] as u32).to_be_bytes());
            let port = words[1] as u16;
            *local_port = local_port.wrapping_add(1).max(49152);
            let local = *local_port;
            {
                let sock = sockets.get_mut::<TcpSocket>(tcp_h);
                sock.abort();
                sock.close();
            }
            poll(iface, phy, sockets);
            let result = sockets.get_mut::<TcpSocket>(tcp_h).connect(iface.context(), (ip, port), local);
            if result.is_err() || !wait_connect(iface, phy, sockets, tcp_h) {
                reply(MsgInfo::new(proto::stack::CONNECT, 1), [1, 0, 0, 0]);
                return;
            }
            reply(MsgInfo::new(proto::stack::CONNECT, 1), [0, 1, 0, 0]);
        }
        proto::stack::SEND => {
            let n = (words[1] as usize).min(4000);
            let mut data = alloc::vec![0u8; n];
            unsafe { core::ptr::copy_nonoverlapping(LENT_VA as *const u8, data.as_mut_ptr(), n) };
            let mut off = 0;
            for _ in 0..2000 {
                poll(iface, phy, sockets);
                let sock = sockets.get_mut::<TcpSocket>(tcp_h);
                if off == n {
                    break;
                }
                if let Ok(sent) = sock.send_slice(&data[off..]) {
                    off += sent;
                }
            }
            reply(MsgInfo::new(proto::stack::SEND, 1), [u64::from(off != n), off as u64, 0, 0]);
        }
        proto::stack::RECV => {
            let mut buf = [0u8; 4000];
            let mut got = 0;
            for _ in 0..500 {
                poll(iface, phy, sockets);
                let sock = sockets.get_mut::<TcpSocket>(tcp_h);
                if sock.can_recv() {
                    got = sock.recv_slice(&mut buf).unwrap_or(0);
                    break;
                }
                if !sock.is_open() {
                    break;
                }
            }
            if got > 0 {
                unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), LENT_VA as *mut u8, got) };
            }
            reply(MsgInfo::new(proto::stack::RECV, 1), [got as u64, 0, 0, 0]);
        }
        proto::stack::CLOSE => {
            sockets.get_mut::<TcpSocket>(tcp_h).close();
            poll(iface, phy, sockets);
            reply(MsgInfo::new(proto::stack::CLOSE, 0), [0; 4]);
        }
        proto::stack::UDP => {
            let ip = Ipv4Address::from_bytes(&(words[0] as u32).to_be_bytes());
            let port = words[1] as u16;
            let n = (words[2] as usize).min(512);
            let mut query = alloc::vec![0u8; n];
            unsafe { core::ptr::copy_nonoverlapping(LENT_VA as *const u8, query.as_mut_ptr(), n) };
            let endpoint = IpEndpoint::new(IpAddress::Ipv4(ip), port);
            let sent = {
                let sock = sockets.get_mut::<UdpSocket>(udp_h);
                sock.send_slice(&query, endpoint).is_ok()
            };
            if !sent {
                reply(MsgInfo::new(proto::stack::UDP, 1), [0, 0, 0, 0]);
                return;
            }
            let mut response = [0u8; 512];
            let mut got = 0;
            for _ in 0..400 {
                poll(iface, phy, sockets);
                let sock = sockets.get_mut::<UdpSocket>(udp_h);
                if let Ok((len, _)) = sock.recv_slice(&mut response) {
                    got = len;
                    break;
                }
            }
            if got > 0 {
                unsafe { core::ptr::copy_nonoverlapping(response.as_ptr(), LENT_VA as *mut u8, got) };
            }
            reply(MsgInfo::new(proto::stack::UDP, 1), [got as u64, 0, 0, 0]);
        }
        _ => {
            reply(MsgInfo::new(0xfff, 0), [0; 4]);
        }
    }
}

fn main(_: u64, _: u64) -> u64 {
    let mut done = 0u64;
    while done < HEAP_PAGES {
        let got = alloc_frames(HEAP + done, (HEAP_PAGES - done).min(3));
        if got == 0 {
            println!("netstack: no heap");
            return 1;
        }
        for i in 0..got {
            map(SPACE, HEAP + done + i, HEAP_VA + (done + i) * 4096, method::WRITE).ok();
        }
        done += got;
    }
    unsafe { ALLOC.lock().init(HEAP_VA as *mut u8, (HEAP_PAGES * 4096) as usize) };
    if alloc_frames(FRAME, 1) != 1 || map(SPACE, FRAME, FRAME_VA, method::WRITE).is_err() {
        println!("netstack: no transfer frame");
        return 1;
    }
    let _ = phys(FRAME);
    let mac = Nic::mac();
    println!("netstack: mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    let mut phy = Phy { rx: VecDeque::new(), tx: VecDeque::new() };
    let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    config.random_seed = 0xA05u64;
    let mut iface = Interface::new(config, &mut phy, now());
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(IpAddress::Ipv4(LOCAL_IP), 24)).unwrap();
    });
    iface.routes_mut().add_default_ipv4_route(GATEWAY).unwrap();

    let rx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 8192]);
    let tx_buf = tcp::SocketBuffer::new(alloc::vec![0u8; 8192]);
    let tcp_socket = TcpSocket::new(rx_buf, tx_buf);
    let udp_rx = udp::PacketBuffer::new(alloc::vec![udp::PacketMetadata::EMPTY; 4], alloc::vec![0u8; 2048]);
    let udp_tx = udp::PacketBuffer::new(alloc::vec![udp::PacketMetadata::EMPTY; 4], alloc::vec![0u8; 2048]);
    let mut udp_socket = UdpSocket::new(udp_rx, udp_tx);
    udp_socket.bind(5353).unwrap();

    let mut sockets = SocketSet::new(Vec::new());
    let tcp_h = sockets.add(tcp_socket);
    let udp_h = sockets.add(udp_socket);
    let mut local_port = 49152u16;
    println!("netstack: ready 10.0.2.15");

    loop {
        poll(&mut iface, &mut phy, &mut sockets);
        for (slot, outbound) in [(OUT_EP, true), (IN_EP, false)] {
            ipc_buffer().recv_slot = LENT;
            let r = recv(slot, 1_000_000);
            if !r.is_ok() {
                continue;
            }
            if r.info.caps() >= 1 {
                let _ = map(SPACE, LENT, LENT_VA, method::WRITE);
            }
            handle(outbound, r.info.label(), r.words, &mut iface, &mut phy, &mut sockets, tcp_h, udp_h, &mut local_port);
            if r.info.caps() >= 1 {
                let _ = aos_rt::cap::unmap(LENT);
                let _ = aos_rt::cap::delete(2, LENT);
            }
        }
    }
}
