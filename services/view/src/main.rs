//! View server for B-4: it holds only the inbound endpoint. BS6 asks it to originate a
//! connection with that capability; the netstack must refuse.

#![no_std]
#![no_main]

use aos_rt::abi::MsgInfo;
use aos_rt::call;
use aos_rt::println;
use aos_rt::proto;

aos_rt::entry!(main);

const INBOUND: u64 = 1;

fn main(_: u64, _: u64) -> u64 {
    // 1.1.1.1:443. The address does not matter: the endpoint itself cannot connect.
    let r = call(INBOUND, MsgInfo::new(proto::stack::CONNECT, 2), [0x0101_0101, 443, 0, 0], 0);
    if r.is_ok() && r.info.label() == proto::stack::DENIED {
        println!("view: BS6 inbound connect refused");
        0
    } else {
        println!("view: BS6 unexpected reply status {} label {}", r.status, r.info.label());
        1
    }
}
