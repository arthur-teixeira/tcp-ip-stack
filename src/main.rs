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
mod test_utils;
mod socket;

struct Interface<T: TunInterface> {
    iface: T,
    arp_cache: ArpCache,
}

fn main() -> Result<()> {
    let mut interface = Interface {
        iface: Iface::without_packet_info("tap1", Mode::Tap)?,
        arp_cache: ArpCache::default(),
    };
    let mut tcp_connections= Connections::default();

    loop {
        let mut sock_buff = BufferView::from_iface(&mut interface.iface)?;
        let frame = Frame::from_buffer(&mut sock_buff);

        match frame.ethertype as c_int {
            libc::ETH_P_ARP => {
                if let Err(e) = arp_recv(frame.payload, &mut interface) {
                    eprintln!("Error: {e}");
                }
            }
            libc::ETH_P_IP => {
                if let Err(e) = ipv4_recv(frame.payload, &mut interface, &mut tcp_connections) {
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
