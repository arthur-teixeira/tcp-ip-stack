use arp::{arp_recv, ArpCache, TunInterface};
use buf_writer::BufWriter;
use buffer_view::BufferView;
use ethernet::Frame;
use ipv4::*;
use libc::{
    c_int, in_addr, sa_family_t, sockaddr, sockaddr_in, AF_INET, INADDR_LOOPBACK, SOCK_DGRAM,
    SOCK_STREAM,
};
use socket::{_accept, _bind, _listen, _socket};
use std::io::{Error, Result};
use tun_tap::{Iface,Mode};
use std::sync::{OnceLock, Mutex};

use crate::socket::_read;

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

struct Interface<T: TunInterface> {
    iface: T,
    arp_cache: ArpCache,
}

fn create_udp_socket() -> Result<i32> {
    let sockfd = _socket(AF_INET, SOCK_DGRAM, 0, None);
    if sockfd < 0 {
        return Err(Error::from_raw_os_error(-sockfd));
    }

    let addr = sockaddr_in {
        sin_port: 5353,
        sin_family: AF_INET as u16,
        sin_addr: in_addr {
            s_addr: INADDR_LOOPBACK,
        },
        sin_zero: [0; 8],
    };

    let bind_result = _bind(
        sockfd,
        &addr as *const sockaddr_in as *const sockaddr,
        std::mem::size_of::<sa_family_t>() as u32,
        None,
    );

    if bind_result < 0 {
        return Err(Error::from_raw_os_error(-bind_result));
    }

    Ok(sockfd)
}

fn create_tcp_socket() -> Result<i32> {
    let sockfd = _socket(AF_INET, SOCK_STREAM, 0, None);
    if sockfd < 0 {
        return Err(Error::from_raw_os_error(-sockfd));
    }

    let addr = sockaddr_in {
        sin_port: 1337,
        sin_family: AF_INET as u16,
        sin_addr: in_addr {
            s_addr: INADDR_LOOPBACK,
        },
        sin_zero: [0; 8],
    };

    let bind_result = _bind(
        sockfd,
        &addr as *const sockaddr_in as *const sockaddr,
        std::mem::size_of::<sa_family_t>() as u32,
        None,
    );

    if bind_result < 0 {
        return Err(Error::from_raw_os_error(-bind_result));
    }

    Ok(sockfd)
}

fn tcp_loop() -> Result<()> {
    let sockfd = create_tcp_socket()?;

    let listen_result = _listen(sockfd, 10, None);
    if listen_result < 0 {
        return Err(Error::from_raw_os_error(-listen_result));
    }

    loop {
        let new_conn = _accept(sockfd, std::ptr::null_mut(), std::ptr::null_mut(), None);
        std::thread::spawn(move || {
            eprintln!("Received new TCP connection!");
            let mut buf = Vec::new();
            loop {
                let rcvd = _read(new_conn, &mut buf, None);
                if rcvd > 0 {
                    eprintln!("---------------------------------");
                    eprintln!("Socket {new_conn} received Data!!");
                    eprintln!("{:?}", String::from_utf8_lossy(&buf));
                    eprintln!("---------------------------------");
                }
            }
        });
    }
}

fn interface() -> &'static Mutex<Interface<Iface>> {
    static IFACE: OnceLock<Mutex<Interface<Iface>>> = OnceLock::new();
    IFACE.get_or_init(|| Mutex::new(Interface {
        iface: Iface::without_packet_info("tap1", Mode::Tap)
            .map_err(|e| eprintln!("Error creating interface: {e:?}"))
            .expect("Expected interface to be created correctly"),
        arp_cache: ArpCache::default(),
    }))
}

fn main() -> Result<()> {

    let ipc_handle = ipc_socket::start_ipc_listener();
    let main_handle = std::thread::spawn(move || {
        loop {
            let mut iface = interface().lock().unwrap();
            let mut sock_buff = BufferView::from_iface(&mut iface.iface).unwrap();
            let frame = Frame::from_buffer(&mut sock_buff);

            match frame.ethertype as c_int {
                libc::ETH_P_ARP => {
                    if let Err(e) = arp_recv(frame.payload, &mut iface) {
                        eprintln!("Error: {e}");
                    }
                }
                libc::ETH_P_IP => {
                    if let Err(e) = ipv4_recv(frame.payload, &mut iface) {
                        eprintln!("Error: {e}");
                    }
                }
                // libc::ETH_P_IPV6 => eprintln!("Receiving IPv6 packet"),
                _ => {
                    continue;
                }
            }
        }
    });

    // let _ = tcp_loop();

    ipc_handle.join().expect("Expected to join ipc thread");
    main_handle.join().expect("Expected to join main thread");

    Ok(())
}
