use std::ffi::c_int;
use std::sync::{Mutex, OnceLock};

use libc::{sockaddr, sockaddr_in, AF_INET, IPPROTO_TCP, IPPROTO_UDP, SOCK_DGRAM, SOCK_STREAM};

#[derive(Debug, PartialEq, Eq)]
pub enum SockType {
    Tcp,
    Udp,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SockState {
    Unbound,
    Bound(u16),
}

impl Default for SockState {
    fn default() -> Self {
        Self::Unbound
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Socket {
    pub stype: SockType,
    pub state: SockState,
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct ConnectionManager {
    pub connections: Vec<Socket>,
    pub current_fd: i32,
}

pub fn cm() -> &'static Mutex<ConnectionManager> {
    static MANAGER: OnceLock<Mutex<ConnectionManager>> = OnceLock::new();
    MANAGER.get_or_init(|| Mutex::new(ConnectionManager::default()))
}

pub extern "C" fn socket(domain: i32, stype: i32, protocol: i32) -> i32 {
    if domain != AF_INET {
        return -1;
    }

    if protocol != 0 {
        match protocol {
            IPPROTO_TCP | IPPROTO_UDP => {},
            _ => return -1,
        }
    }

    let mut manager = cm().lock().expect("poisoned lock");

    let socket_type = match stype as c_int {
        SOCK_DGRAM => SockType::Udp,
        SOCK_STREAM => SockType::Tcp,
        _ => return -1,
    };

    let sock = Socket {
        stype: socket_type,
        state: SockState::default(),
    };

    let fd = manager.current_fd;
    manager.connections.push(sock);
    manager.current_fd += 1;

    return fd;
}

pub extern "C" fn bind(sockfd: i32, addr: *const sockaddr, _sockaddr_len: u32) -> i32 {
    let mut manager = cm().lock().expect("poisoned lock");
    if sockfd > manager.current_fd {
        return -1;
    }

    let sock = &mut manager.connections[sockfd as usize];
    let address: sockaddr_in;
    unsafe {
        if addr == std::ptr::null() {
            return -1;
        }

        if (*addr).sa_family != AF_INET as u16 {
            return -1;
        }
        address = *(addr as *const sockaddr_in);
    }

    sock.state = SockState::Bound(address.sin_port);
    return 1;
}

pub extern "C" fn connect(sockfd: i32, addr: *const sockaddr_in, sockaddr_len: u32) -> i32 {
    todo!()
}
