use arp::{arp_recv, ArpCache, TunInterface};
use buf_writer::BufWriter;
use buffer_view::BufferView;
use ethernet::Frame;
use ipv4::*;
use libc::c_int;
use tcp::Connections;
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
mod tcp;

struct Interface<'a> {
    iface: Box<dyn TunInterface>,
    arp_cache: ArpCache,
    tcp_connections: Connections<'a>,
}

fn main() -> Result<()> {
    let mut interface = Interface {
        iface: Box::new(Iface::without_packet_info("tap1", Mode::Tap)?),
        arp_cache: ArpCache::default(),
        tcp_connections: Connections::default(),
    };

    loop {
        let mut sock_buff = BufferView::from_iface(&mut *interface.iface)?;
        let frame = Frame::from_buffer(&mut sock_buff);

        match frame.ethertype as c_int {
            libc::ETH_P_ARP => {
                eprintln!("Receiving ARP packet");
                if let Err(e) = arp_recv(frame.payload, &mut interface) {
                    eprintln!("Error: {e}");
                }
            }
            libc::ETH_P_IP => {
                eprintln!("Receiving IP packet");
                if let Err(e) = ipv4_recv(frame.payload, &mut interface) {
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
