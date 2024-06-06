use arp::{arp_recv, ArpCache, TunInterface};
use buf_writer::BufWriter;
use buffer_view::BufferView;
use ethernet::Frame;
use ipv4::*;
use libc::c_int;
use route::ROUTES;
use std::io::Result;
use std::sync::{Arc, Mutex};
use tun_tap::{Iface, Mode};

mod arp;
mod buf_writer;
mod buffer_view;
mod ethernet;
mod icmpv4;
mod ipc_socket;
mod ipv4;
mod route;
mod sock_types;
mod socket;
mod tcp;
mod test_utils;
mod udp;
mod utils;

struct AppState<T: TunInterface> {
    iface: T,
    arp_cache: ArpCache,
}

type Interface<T> = Arc<Mutex<AppState<T>>>;

fn main() -> Result<()> {
    let app_state = AppState {
        iface: Iface::without_packet_info("tap1", Mode::Tap)?,
        arp_cache: ArpCache::default(),
    };
    let global_interface: Interface<Iface> = Arc::new(Mutex::new(app_state));
    ipc_socket::start_ipc_listener(global_interface.clone());

    loop {
        let mut interface = global_interface.lock().unwrap();
        let mut sock_buff = BufferView::from_iface(&mut interface.iface).unwrap();
        drop(interface);

        let frame = Frame::from_buffer(&mut sock_buff);

        match frame.ethertype as c_int {
            libc::ETH_P_ARP => {
                if let Err(e) = arp_recv(frame.payload, global_interface.clone()) {
                    eprintln!("Error: {e}");
                }
            }
            libc::ETH_P_IP => {
                if let Err(e) = ipv4_recv(frame.payload, global_interface.clone()) {
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
