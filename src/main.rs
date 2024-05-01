use arp::{arp_recv, ArpCache};
use libc::c_int;
use std::io::Result;
use tun_tap::{Iface, Mode};
use buffer_view::BufferView;
use buf_writer::BufWriter;
use frame::Frame;

use crate::ipv4::ipv4_recv;

mod arp;
mod buffer_view;
mod buf_writer;
mod frame;
mod ipv4;
mod icmpv4;

fn main() -> Result<()> {
    let mut iface = Iface::without_packet_info("tap1", Mode::Tap)?;
    let mut arp_cache = ArpCache::new();

    loop {
        let mut sock_buff = BufferView::from_iface(&mut iface)?;
        let frame = Frame::from_buffer(&mut sock_buff);

        match frame.ethertype as c_int {
            libc::ETH_P_ARP => {
                eprintln!("Receiving ARP packet");
                arp_recv(frame.payload, &mut arp_cache, &mut iface)?;
            }
            libc::ETH_P_IP => {
                eprintln!("Receiving IP packet");
                match ipv4_recv(frame.payload) {
                    Ok(_) => {},
                    Err(e) => eprintln!("Error: {e}"),
                }
            }
            // libc::ETH_P_IPV6 => eprintln!("Receiving IPv6 packet"),
            _ => {
                continue;
            }
        }
    }
}
