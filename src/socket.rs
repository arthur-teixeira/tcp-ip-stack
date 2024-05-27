#![allow(dead_code)]

use std::{
    collections::{LinkedList, VecDeque},
    mem,
    sync::{Mutex, MutexGuard, OnceLock},
};

use libc::{
    accept, bind, c_void, listen, recv, sa_family_t, sockaddr, sockaddr_in, socket, socklen_t,
    AF_INET, EADDRINUSE, EBADF, EINVAL, ENOTSUP, EOPNOTSUPP, IPPROTO_TCP, IPPROTO_UDP, SOCK_DGRAM,
    SOCK_STREAM,
};

use crate::tcp::{Connection, Connections, Quad};

#[derive(Debug, PartialEq)]
pub enum SockProto {
    TcpListener {
        max_backlog_size: usize,
        backlog: Connections,
    },
    TcpStream,
    Udp,
}

impl SockProto {
    fn from(n: i32) -> Self {
        match n {
            SOCK_DGRAM => Self::Udp,
            SOCK_STREAM => Self::TcpListener {
                backlog: Default::default(),
                max_backlog_size: 0,
            },
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum SockState {
    Unbound,
    Bound(u16),     // Port
    Listening(u16), // Port
    Connected { quad: Quad, conn: Connection },
}

#[derive(Debug)]
pub struct Socket {
    pub state: SockState,
    pub proto: SockProto,
    pub fd: i32,

    pub recv_queue: VecDeque<Box<[u8]>>,
    pub send_queue: VecDeque<Box<[u8]>>,
}

impl Socket {
    pub fn listen_port(&self) -> Option<u16> {
        match self.state {
            SockState::Listening(p) => Some(p),
            SockState::Bound(p) => match self.proto {
                SockProto::Udp => Some(p),
                _ => None,
            },
            SockState::Connected { quad, .. } => {
                dbg!(quad);
                Some(quad.dst.1)
            }
            _ => None,
        }
    }

    pub fn listening(&self) -> bool {
        match self.state {
            SockState::Listening(_) | SockState::Connected { .. } => true,
            _ => false,
        }
    }
}

pub struct SocketManager {
    pub socks: LinkedList<Socket>,
    pub stream_socks: LinkedList<Socket>,
    pub fd: i32,
}

impl SocketManager {
    pub fn get_sock(&mut self, sockfd: i32) -> Option<&mut Socket> {
        self.socks
            .iter_mut()
            .find(|s| s.fd == sockfd)
            .or(self.stream_socks.iter_mut().find(|s| s.fd == sockfd))
    }

    pub fn get_sock_by_quad(&mut self, search_quad: &Quad) -> Option<&mut Socket> {
        self.stream_socks
            .iter_mut()
            .find(|s| match s.proto {
                SockProto::TcpStream => match s.state {
                    SockState::Connected { quad, .. } => quad == *search_quad,
                    _ => false,
                },
                _ => false,
            })
            .or(self.socks.iter_mut().find(|s| match s.listen_port() {
                None => false,
                Some(p) => p == search_quad.dst.1 && s.listening(),
            }))
    }
}

impl Default for SocketManager {
    fn default() -> Self {
        Self {
            socks: LinkedList::new(),
            stream_socks: LinkedList::new(),
            fd: 4097,
        }
    }
}

pub fn sockets() -> &'static Mutex<SocketManager> {
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
        proto: SockProto::from(stype),
        state: SockState::Unbound,
        fd,
        recv_queue: Default::default(),
        send_queue: Default::default(),
    };

    mgr.socks.push_back(sock);
    mgr.fd += 1;

    fd
}

pub fn _bind(
    sockfd: i32,
    addr: *const sockaddr,
    addrlen: socklen_t,
    manager: Option<&Mutex<SocketManager>>,
) -> i32 {
    let mut socket = None;

    if addr.is_null() || (addrlen as usize) < mem::size_of::<sa_family_t>() {
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

fn get_highest_port<'a>(manager: &MutexGuard<'a, SocketManager>) -> u16 {
    manager.socks.iter().fold(1024, |acc, s| {
        if let SockState::Bound(port) = s.state {
            if port > acc {
                return port;
            }
            return acc;
        }

        if let SockState::Listening(port) = s.state {
            if port > acc {
                return port;
            }

            return acc;
        }

        return acc;
    })
}

pub fn _listen(sockfd: i32, max_backlog: i32, manager: Option<&Mutex<SocketManager>>) -> i32 {
    let manager = manager.unwrap_or(sockets());
    let mut mgr = manager.lock().unwrap();
    let highest_port = get_highest_port(&mgr) + 1;

    let sock = mgr.get_sock(sockfd);

    if let Some(sock) = sock {
        if let SockProto::Udp = sock.proto {
            return -ENOTSUP;
        }
        let port = match sock.state {
            SockState::Unbound => highest_port,
            SockState::Listening(_) => return 0,
            SockState::Bound(port) => port,
            SockState::Connected { .. } => return -EOPNOTSUPP,
        };

        sock.state = SockState::Listening(port);
        sock.proto = SockProto::TcpListener {
            max_backlog_size: max_backlog as usize,
            backlog: Default::default(),
        };

        0
    } else {
        unsafe { listen(sockfd, max_backlog) }
    }
}

pub fn _accept(
    sockfd: i32,
    addr: *mut sockaddr,
    addrlen: *mut socklen_t,
    manager: Option<&Mutex<SocketManager>>,
) -> i32 {
    loop {
        let mut mgr = manager.unwrap_or(sockets()).lock().unwrap();
        let fd = mgr.fd;
        let sock = mgr.get_sock(sockfd);

        if let Some(sock) = sock {
            if sock.proto == SockProto::Udp {
                return -EOPNOTSUPP;
            }
            if !sock.listening() {
                return -EBADF;
            }

            if let SockProto::TcpListener {
                ref mut max_backlog_size,
                ref mut backlog,
            } = sock.proto
            {
                if !backlog.is_empty() {
                    *max_backlog_size -= 1;
                    let (quad, conn) = backlog
                        .pop_first()
                        .expect("Expected backlog not to be empty");

                    let new_sock = Socket {
                        proto: SockProto::TcpStream,
                        state: SockState::Connected { quad, conn },
                        fd,
                        recv_queue: Default::default(),
                        send_queue: Default::default(),
                    };

                    mgr.fd += 1;
                    mgr.stream_socks.push_back(new_sock);
                    if !addr.is_null() {
                        if addrlen.is_null() {
                            return -EINVAL;
                        }
                        let mut addr_in;
                        unsafe {
                            addr_in = *(addr as *mut sockaddr_in);
                            *addrlen = std::mem::size_of::<sockaddr_in>() as u32;
                        }
                        addr_in.sin_port = quad.src.1;
                        addr_in.sin_family = AF_INET as u16;
                        addr_in.sin_addr.s_addr = quad.src.0.into();
                    }

                    return fd;
                }
            } else {
                return -EINVAL;
            }
        } else {
            return unsafe { accept(sockfd, addr, addrlen) };
        }
    }
}

// ssize_t recv(int sockfd, void *buf, size_t len, int flags);
// TODO: use flags
// TODO: change the loop to wait for a condvar before reading from socket buffer again.
// TODO: Change buf to be a slice of u8
pub fn _recv(sockfd: i32, buf: &mut Vec<u8>) -> isize {
    loop {
        let manager = sockets();
        let mut mgr = manager.lock().unwrap();
        let sock = mgr.get_sock(sockfd);

        if let Some(sock) = sock {
            if !sock.recv_queue.is_empty() {
                let msg = sock
                    .recv_queue
                    .pop_front()
                    .expect("expected recv queue to have item");

                buf.extend_from_slice(&msg);
                return msg.len() as isize;
            }
        } else {
            return unsafe { recv(sockfd, buf.as_slice().as_ptr() as *mut c_void, buf.len(), 0) };
        }
    }
}

pub fn _connect(sockfd: i32, addr: *const sockaddr, addrlen: socklen_t) -> i32 {
    unimplemented!()
}

#[cfg(test)]
mod socket_test {
    use std::{mem, sync::Mutex};

    use libc::{
        in_addr, sa_family_t, sockaddr, sockaddr_in, AF_INET, EADDRINUSE, EINVAL, ENOTSUP,
        SOCK_DGRAM, SOCK_STREAM,
    };

    use super::{SockProto, SockState, SocketManager, _bind, _listen, _socket};

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
        assert_eq!(
            sock.proto,
            SockProto::TcpListener {
                max_backlog_size: 0,
                backlog: Default::default(),
            }
        );
        assert!(result > 0);
    }

    #[test]
    fn test_udp_socket() {
        let mgr = new_mgr();
        let result = _socket(AF_INET, SOCK_DGRAM, 0, Some(&mgr));
        let mgr = mgr.lock().unwrap();
        let sock = mgr.socks.front().expect("Expected socket to be created");

        assert_eq!(sock.state, SockState::Unbound);
        assert_eq!(sock.proto, SockProto::Udp);
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

    #[test]
    fn test_udp_listen() {
        let mgr = new_mgr();
        let sock = _socket(AF_INET, SOCK_DGRAM, 0, Some(&mgr));
        assert!(sock > 0);
        let addr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: 8080,
            sin_addr: in_addr { s_addr: 123 },
            sin_zero: [0; 8],
        };

        let bind_result = _bind(
            sock,
            &addr as *const sockaddr_in as *const sockaddr,
            mem::size_of::<sa_family_t>() as u32,
            Some(&mgr),
        );
        assert_eq!(bind_result, 0);

        let listen_result = _listen(sock, 10, Some(&mgr));

        assert_eq!(listen_result, -ENOTSUP);
    }

    #[test]
    fn test_tcp_listen() {
        let mgr = new_mgr();
        let sock = _socket(AF_INET, SOCK_STREAM, 0, Some(&mgr));
        assert!(sock > 0);

        let addr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: 8080,
            sin_addr: in_addr { s_addr: 123 },
            sin_zero: [0; 8],
        };

        let bind_result = _bind(
            sock,
            &addr as *const sockaddr_in as *const sockaddr,
            mem::size_of::<sa_family_t>() as u32,
            Some(&mgr),
        );
        assert_eq!(bind_result, 0);

        let listen_result = _listen(sock, 10, Some(&mgr));
        assert_eq!(listen_result, 0);
    }

    #[test]
    fn test_unbound_listen() {
        let mgr = new_mgr();
        let sock = _socket(AF_INET, SOCK_STREAM, 0, Some(&mgr));
        assert!(sock > 0);

        let listen_result = _listen(sock, 10, Some(&mgr));
        assert_eq!(listen_result, 0);
    }
}
