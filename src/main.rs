use arp::{arp_recv, ArpCache};
use buf_writer::BufWriter;
use buffer_view::BufferView;
use ethernet::Frame;
use ipv4::*;
use libc::c_int;
use std::io::Result;
use tun_tap::{Iface, Mode};

mod arp;
mod buf_writer;
mod buffer_view;
mod ethernet;
mod icmpv4;
mod ipv4;
mod udp;
mod utils;

fn main() -> Result<()> {
    let mut iface = Iface::without_packet_info("tap1", Mode::Tap)?;
    let mut arp_cache = ArpCache::new();

    loop {
        let mut sock_buff = BufferView::from_iface(&mut iface)?;
        let frame = Frame::from_buffer(&mut sock_buff);

        match frame.ethertype as c_int {
            libc::ETH_P_ARP => {
                eprintln!("Receiving ARP packet");
                if let Err(e) = arp_recv(frame.payload, &mut arp_cache, &mut iface) {
                    eprintln!("Error: {e}");
                }
            }
            libc::ETH_P_IP => {
                eprintln!("Receiving IP packet");
                if let Err(e) = ipv4_recv(frame.payload, &arp_cache, &mut iface) {
                    eprintln!("Error: {e}");
                }
            }
            // libc::ETH_P_IPV6 => eprintln!("Receiving IPv6 packet"),
            _ => {
                continue;
            }
        }
    }
}
