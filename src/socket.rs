#![allow(dead_code)]

use std::{
    collections::LinkedList,
    mem,
    sync::{OnceLock, RwLock},
};

use libc::{
    bind, sa_family_t, sockaddr, sockaddr_in, socket, socklen_t, AF_INET, EADDRINUSE, EBADF,
    EINVAL, ENOTSUP, IPPROTO_TCP, IPPROTO_UDP, SOCK_DGRAM, SOCK_STREAM,
};

use crate::tcp::Connection;

#[derive(Debug, PartialEq)]
pub enum SockType {
    Tcp {
        max_backlog_size: usize,
        backlog_size: usize,
        backlog: Vec<Connection>,
    },
    Udp,
}

impl SockType {
    fn from(n: i32) -> Self {
        match n {
            SOCK_DGRAM => Self::Udp,
            SOCK_STREAM => Self::Tcp {
                backlog: vec![],
                max_backlog_size: 0,
                backlog_size: 0,
            },
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SockState {
    Unbound,
    Bound(u16),     // Port
    Listening(u16), // Port
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

fn sockets() -> &'static RwLock<SocketManager> {
    static SOCKS: OnceLock<RwLock<SocketManager>> = OnceLock::new();
    SOCKS.get_or_init(|| RwLock::new(SocketManager::default()))
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
    manager: Option<&RwLock<SocketManager>>,
) -> i32 {
    if !is_accepted_type(domain, stype, protocol) {
        return unsafe { socket(domain, stype, protocol) };
    };

    let mut mgr = manager.unwrap_or(sockets()).write().unwrap();

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
    manager: Option<&RwLock<SocketManager>>,
) -> i32 {
    let mut socket = None;

    if addr.is_null() || (addrlen as usize) < mem::size_of::<sa_family_t>() {
        return -EINVAL;
    }

    let address = unsafe { *(addr as *const sockaddr_in) };
    let mut mgr = manager.unwrap_or(sockets()).write().unwrap();

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

pub fn _listen(sockfd: i32, max_backlog: i32, manager: Option<&RwLock<SocketManager>>) -> i32 {
    let mut mgr = manager.unwrap_or(sockets()).write().unwrap();
    let sock = mgr.socks.iter_mut().find(|s| s.fd == sockfd);

    if let Some(sock) = sock {
        if let SockType::Udp = sock.stype {
            return -ENOTSUP;
        }
        let port = match sock.state {
            SockState::Unbound => return -EBADF,
            SockState::Listening(_) => return 0,
            SockState::Bound(port) => port,
        };
        sock.state = SockState::Listening(port);
        sock.stype = SockType::Tcp {
            max_backlog_size: max_backlog as usize,
            backlog_size: 0,
            backlog: vec![],
        };

        0
    } else {
        -EBADF
    }
}

#[cfg(test)]
mod socket_test {
    use std::{mem, sync::RwLock};

    use libc::{
        in_addr, sa_family_t, sockaddr, sockaddr_in, AF_INET, EADDRINUSE, EINVAL, SOCK_DGRAM,
        SOCK_STREAM,
    };

    use crate::socket::{SocketManager, _bind};

    use super::{SockState, SockType, _socket};

    fn new_mgr() -> RwLock<SocketManager> {
        RwLock::new(SocketManager::default())
    }

    #[test]
    fn test_tcp_socket() {
        let mgr = new_mgr();
        let result = _socket(AF_INET, SOCK_STREAM, 0, Some(&mgr));
        let mgr = mgr.read().unwrap();
        let sock = mgr.socks.front().expect("Expected socket to be created");

        assert_eq!(sock.state, SockState::Unbound);
        assert_eq!(
            sock.stype,
            SockType::Tcp {
                backlog_size: 0,
                max_backlog_size: 0,
                backlog: vec![],
            }
        );
        assert!(result > 0);
    }

    #[test]
    fn test_udp_socket() {
        let mgr = new_mgr();
        let result = _socket(AF_INET, SOCK_DGRAM, 0, Some(&mgr));
        let mgr = mgr.read().unwrap();
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

        let mgr = mgr.read().unwrap();

        let sock = mgr.socks.front().expect("Expected socket");
        assert_eq!(bind_result, 0);
        assert_eq!(sock.state, SockState::Bound(8080));
    }

    #[test]
    fn test_bind_duplicate_port() {
        let mgr = new_mgr();
        let sockfd1 = _socket(AF_INET, SOCK_STREAM, 0, Some(&mgr));
        let sockfd2 = _socket(AF_INET, SOCK_STREAM, 0, Some(&mgr));
        assert!(sockfd1 > 0);
        assert!(sockfd2 > 0);
        let addr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: 8080,
            sin_addr: in_addr { s_addr: 123 },
            sin_zero: [0; 8],
        };

        let bind_result = _bind(
            sockfd1,
            &addr as *const sockaddr_in as *const sockaddr,
            mem::size_of::<sockaddr_in>() as u32,
            Some(&mgr),
        );
        assert_eq!(bind_result, 0);
        let bind_result = _bind(
            sockfd2,
            &addr as *const sockaddr_in as *const sockaddr,
            mem::size_of::<sockaddr_in>() as u32,
            Some(&mgr),
        );
        assert_eq!(bind_result, -EADDRINUSE);
    }

    #[test]
    fn test_bind_invalid_sockaddr() {
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
            mem::size_of::<u8>() as u32,
            Some(&mgr),
        );
        assert_eq!(bind_result, -EINVAL);
    }

    #[test]
    fn test_bind_null_addr() {
        let mgr = new_mgr();
        let bind_result = _bind(
            1,
            std::ptr::null(),
            mem::size_of::<sa_family_t>() as u32,
            Some(&mgr),
        );
        assert_eq!(bind_result, -EINVAL);
    }
}
