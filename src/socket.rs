#![allow(dead_code)]

use std::{
    collections::LinkedList,
    mem,
    sync::{Mutex, OnceLock},
};

use libc::{
    bind, sa_family_t, sockaddr, sockaddr_in, socket, socklen_t, AF_INET, EADDRINUSE, EINVAL,
    IPPROTO_TCP, IPPROTO_UDP, SOCK_DGRAM, SOCK_STREAM,
};

#[derive(Debug, PartialEq, Eq)]
pub enum SockType {
    Tcp,
    Udp,
}

impl SockType {
    fn from(n: i32) -> Self {
        match n {
            SOCK_DGRAM => Self::Udp,
            SOCK_STREAM => Self::Tcp,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SockState {
    Unbound,
    Bound(u16), // Port
}

#[derive(Debug)]
pub struct Socket {
    state: SockState,
    stype: SockType,
    fd: i32,
}

pub struct SocketManager {
    socks: LinkedList<Socket>,
    fd: i32,
}

impl Default for SocketManager {
    fn default() -> Self {
        Self {
            socks: LinkedList::new(),
            fd: 4097,
        }
    }
}

fn sockets() -> &'static Mutex<SocketManager> {
    static SOCKS: OnceLock<Mutex<SocketManager>> = OnceLock::new();
    SOCKS.get_or_init(|| Mutex::new(SocketManager::default()))
}

fn is_accepted_type(domain: i32, stype: i32, protocol: i32) -> bool {
    if domain != AF_INET {
        return false;
    }

    match stype {
        SOCK_STREAM | SOCK_DGRAM => {}
        _ => return false,
    };

    if protocol != 0 {
        return protocol == IPPROTO_TCP || protocol == IPPROTO_UDP;
    }

    return true;
}

pub fn _socket(
    domain: i32,
    stype: i32,
    protocol: i32,
    manager: Option<&Mutex<SocketManager>>,
) -> i32 {
    if !is_accepted_type(domain, stype, protocol) {
        return unsafe { socket(domain, stype, protocol) };
    };

    let mut mgr = manager.unwrap_or(sockets()).lock().unwrap();

    let fd = mgr.fd;

    let sock = Socket {
        stype: SockType::from(stype),
        state: SockState::Unbound,
        fd,
    };

    mgr.socks.push_back(sock);
    mgr.fd += 1;

    return fd;
}

pub fn _bind(
    sockfd: i32,
    addr: *const sockaddr,
    addrlen: socklen_t,
    manager: Option<&Mutex<SocketManager>>,
) -> i32 {
    let mut socket = None;

    if (addrlen as usize) < mem::size_of::<sa_family_t>() {
        return -EINVAL;
    }

    let address = unsafe { *(addr as *const sockaddr_in) };
    let mut mgr = manager.unwrap_or(sockets()).lock().unwrap();

    for sock in mgr.socks.iter_mut() {
        if let SockState::Bound(port) = sock.state {
            if port == address.sin_port {
                return -EADDRINUSE;
            }
        }

        if sock.fd == sockfd {
            socket = Some(sock);
        }
    }

    if let Some(sock) = socket {
        sock.state = SockState::Bound(address.sin_port);
        return 0;
    } else {
        eprintln!("Unsupported socket type, binding to OS socket");
        return unsafe { bind(sockfd, addr, addrlen) };
    }
}

#[cfg(test)]
mod socket_test {
    use std::{mem, sync::Mutex};

    use libc::{in_addr, sockaddr, sockaddr_in, AF_INET, SOCK_DGRAM, SOCK_STREAM};

    use crate::socket::{SocketManager, _bind};

    use super::{SockState, SockType, _socket};

    fn new_mgr() -> Mutex<SocketManager> {
        Mutex::new(SocketManager::default())
    }

    #[test]
    fn test_tcp_socket() {
        let mgr = new_mgr();
        let result = _socket(AF_INET, SOCK_STREAM, 0, Some(&mgr));
        let mgr = mgr.lock().unwrap();
        let sock = mgr.socks.front().expect("Expected socket to be created");

        assert_eq!(sock.state, SockState::Unbound);
        assert_eq!(sock.stype, SockType::Tcp);
        assert!(result > 0);
    }

    #[test]
    fn test_udp_socket() {
        let mgr = new_mgr();
        let result = _socket(AF_INET, SOCK_DGRAM, 0, Some(&mgr));
        let mgr = mgr.lock().unwrap();
        let sock = mgr.socks.front().expect("Expected socket to be created");

        assert_eq!(sock.state, SockState::Unbound);
        assert_eq!(sock.stype, SockType::Udp);
        assert!(result > 0);
    }

    #[test]
    fn test_bind_socket() {
        let mgr = new_mgr();
        let sockfd = _socket(AF_INET, SOCK_STREAM, 0, Some(&mgr));
        assert!(sockfd > 0);

        let addr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: 8080,
            sin_addr: in_addr { s_addr: 123 },
            sin_zero: [0; 8],
        };

        let bind_result = _bind(
            sockfd,
            &addr as *const sockaddr_in as *const sockaddr,
            mem::size_of::<sockaddr_in>() as u32,
            Some(&mgr),
        );

        let mgr = mgr.lock().unwrap();

        let sock = mgr.socks.front().expect("Expected socket");
        assert!(bind_result == 0);
        assert_eq!(sock.state, SockState::Bound(8080));
    }
}
