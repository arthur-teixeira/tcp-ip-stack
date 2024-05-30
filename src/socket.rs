#![allow(dead_code)]

use std::{
    collections::{
        linked_list::{Iter, IterMut},
        LinkedList, VecDeque,
    },
    iter::FilterMap,
    mem,
    sync::{Mutex, MutexGuard, OnceLock},
};

use libc::{
    accept, bind, c_void, listen, recv, sa_family_t, sockaddr, sockaddr_in, socket, socklen_t,
    AF_INET, AF_UNSPEC, EADDRINUSE, EAFNOSUPPORT, EBADF, EINVAL, ENOTSUP, EOPNOTSUPP, INADDR_ANY,
    IPPROTO_TCP, IPPROTO_UDP, SOCK_DGRAM, SOCK_STREAM,
};

use crate::tcp::{Connection, Connections, Quad};

trait SockOps {
    fn bind(&mut self, addr: *const sockaddr, addrlen: socklen_t) -> i32;
    fn listen(&mut self, backlog: i32, highest_port: u16) -> i32;
    fn accept(
        &mut self,
        addr: *mut sockaddr,
        addrlen: *mut socklen_t,
        cur_fd: i32,
    ) -> Result<Option<SocketKind>, i32>;
    fn read(&mut self, buf: &mut Vec<u8>) -> Option<isize>;
    fn connect(&mut self, addr: *const sockaddr, addrlen: socklen_t) -> i32;
    fn write(&mut self, buf: &Vec<u8>) -> i32;
}

#[derive(Debug, PartialEq)]
pub enum SocketKind {
    Tcp(TcpSocket),
    Udp(UdpSocket),
}

impl SockOps for SocketKind {
    fn connect(&mut self, addr: *const sockaddr, addrlen: socklen_t) -> i32 {
        match self {
            Self::Tcp(tcp) => tcp.connect(addr, addrlen),
            Self::Udp(udp) => udp.connect(addr, addrlen),
        }
    }

    fn accept(
        &mut self,
        addr: *mut sockaddr,
        addrlen: *mut socklen_t,
        cur_fd: i32,
    ) -> Result<Option<SocketKind>, i32> {
        match self {
            Self::Tcp(tcp) => tcp.accept(addr, addrlen, cur_fd),
            Self::Udp(udp) => udp.accept(addr, addrlen, cur_fd),
        }
    }

    fn listen(&mut self, backlog: i32, highest_port: u16) -> i32 {
        match self {
            Self::Tcp(tcp) => tcp.listen(backlog, highest_port),
            Self::Udp(udp) => udp.listen(backlog, highest_port),
        }
    }

    fn read(&mut self, buf: &mut Vec<u8>) -> Option<isize> {
        match self {
            Self::Tcp(tcp) => tcp.read(buf),
            Self::Udp(udp) => udp.read(buf),
        }
    }

    fn bind(&mut self, addr: *const sockaddr, addrlen: socklen_t) -> i32 {
        match self {
            Self::Tcp(tcp) => tcp.bind(addr, addrlen),
            Self::Udp(udp) => udp.bind(addr, addrlen),
        }
    }

    fn write(&mut self, buf: &Vec<u8>) -> i32 {
        match self {
            Self::Tcp(tcp) => tcp.write(buf),
            Self::Udp(udp) => udp.write(buf),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct UdpSocket {
    pub state: SockState,
    pub recv_queue: VecDeque<Box<[u8]>>,
}

impl SockOps for UdpSocket {
    fn bind(&mut self, addr: *const sockaddr, addrlen: socklen_t) -> i32 {
        if addr.is_null() || (addrlen as usize) < mem::size_of::<sa_family_t>() {
            return -EINVAL;
        }
        let address = unsafe { *(addr as *const sockaddr_in) };

        if address.sin_family != AF_INET as u16 {
            if address.sin_family != AF_UNSPEC as u16 || address.sin_addr.s_addr != INADDR_ANY {
                return -EAFNOSUPPORT;
            }
        }

        self.state = SockState::Bound(address.sin_port);
        0
    }

    fn read(&mut self, buf: &mut Vec<u8>) -> Option<isize> {
        self.recv_queue.pop_front().and_then(|msg| {
            buf.extend_from_slice(&msg[0..=buf.capacity()]);
            Some(msg.len() as isize)
        })
    }

    fn listen(&mut self, _backlog: i32, _highest_port: u16) -> i32 {
        -ENOTSUP
    }

    fn accept(
        &mut self,
        _addr: *mut sockaddr,
        _addrlen: *mut socklen_t,
        _cur_fd: i32,
    ) -> Result<Option<SocketKind>, i32> {
        Err(-EINVAL)
    }

    fn connect(&mut self, _addr: *const sockaddr, _addrlen: socklen_t) -> i32 {
        todo!()
    }

    fn write(&mut self, _buf: &Vec<u8>) -> i32 {
        todo!()
    }
}

#[derive(Debug, PartialEq)]
pub struct TcpSocket {
    pub fd: i32,
    pub state: SockState,
    pub stype: TcpType,
    pub recv_queue: VecDeque<Box<[u8]>>,
}

impl TcpSocket {
    fn listening(&self) -> bool {
        match self.state {
            SockState::Listening(_) | SockState::Connected { .. } => true,
            _ => false,
        }
    }
}

impl SockOps for TcpSocket {
    fn bind(&mut self, addr: *const sockaddr, addrlen: socklen_t) -> i32 {
        if addr.is_null() || (addrlen as usize) < mem::size_of::<sa_family_t>() {
            return -EINVAL;
        }
        let address = unsafe { *(addr as *const sockaddr_in) };

        if address.sin_family != AF_INET as u16 {
            if address.sin_family != AF_UNSPEC as u16 || address.sin_addr.s_addr != INADDR_ANY {
                return -EAFNOSUPPORT;
            }
        }

        self.state = SockState::Bound(address.sin_port);
        0
    }

    fn listen(&mut self, backlog: i32, highest_port: u16) -> i32 {
        let port = match self.state {
            SockState::Unbound => highest_port,
            SockState::Listening(_) => return 0,
            SockState::Bound(port) => port,
            SockState::Connected { .. } => return -EOPNOTSUPP,
        };

        self.state = SockState::Listening(port);
        self.stype = TcpType::TcpListener {
            max_backlog_size: backlog as usize,
            backlog: Default::default(),
        };

        0
    }

    fn accept(
        &mut self,
        addr: *mut sockaddr,
        addrlen: *mut socklen_t,
        cur_fd: i32,
    ) -> Result<Option<SocketKind>, i32> {
        if !self.listening() {
            return Err(-EBADF);
        }

        if let TcpType::TcpListener {
            ref mut max_backlog_size,
            ref mut backlog,
        } = self.stype
        {
            if !backlog.is_empty() {
                *max_backlog_size -= 1;
                let (quad, conn) = backlog
                    .pop_first()
                    .expect("Expected backlog not to be empty");

                let new_sock = TcpSocket {
                    stype: TcpType::TcpStream,
                    state: SockState::Connected { quad, conn },
                    fd: cur_fd,
                    recv_queue: Default::default(),
                };
                if !addr.is_null() {
                    if addrlen.is_null() {
                        return Err(-EINVAL);
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

                Ok(Some(SocketKind::Tcp(new_sock)))
            } else {
                Ok(None)
            }
        } else {
            Err(-EINVAL)
        }
    }

    fn read(&mut self, buf: &mut Vec<u8>) -> Option<isize> {
        self.recv_queue.pop_front().and_then(|msg| {
            buf.extend_from_slice(&msg[0..=buf.capacity()]);
            Some(msg.len() as isize)
        })
    }

    fn connect(&mut self, addr: *const sockaddr, addrlen: socklen_t) -> i32 {
        todo!()
    }

    fn write(&mut self, buf: &Vec<u8>) -> i32 {
        todo!()
    }
}

#[derive(Debug, PartialEq)]
pub enum TcpType {
    TcpListener {
        max_backlog_size: usize,
        backlog: Connections,
    },
    TcpStream,
}

#[derive(Debug, PartialEq)]
pub enum SockState {
    Unbound,
    Bound(u16),     // Port
    Listening(u16), // Port
    Connected { quad: Quad, conn: Connection },
}

impl SockState {
    pub fn port(&self) -> Option<u16> {
        match self {
            Self::Bound(p) | Self::Listening(p) => Some(*p),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Socket {
    pub fd: i32,
    pub sock: SocketKind,
}

// impl Socket {
//     pub fn listen_port(&self) -> Option<u16> {
//         match self.state {
//             SockState::Listening(p) => Some(p),
//             SockState::Bound(p) => match self.proto {
//                 SockType::Udp => Some(p),
//                 _ => None,
//             },
//             SockState::Connected { quad, .. } => {
//                 dbg!(quad);
//                 Some(quad.dst.1)
//             }
//             _ => None,
//         }
//     }
//
//     pub fn listening(&self) -> bool {
//         match self.state {
//             SockState::Listening(_) | SockState::Connected { .. } => true,
//             _ => false,
//         }
//     }
// }

#[derive(Debug)]
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

    pub fn get_sock_by_quad(&mut self, search_quad: &Quad) -> Option<&mut TcpSocket> {
        let mut tcp_streams =
            self.stream_socks
                .iter_mut()
                .filter_map(|s: &mut Socket| match s.sock {
                    SocketKind::Tcp(ref mut sock) => Some(sock),
                    _ => None,
                });

        let mut tcp_listeners = self
            .socks
            .iter_mut()
            .filter_map(|s: &mut Socket| match s.sock {
                SocketKind::Tcp(ref mut sock) => Some(sock),
                _ => None,
            });

        tcp_streams
            .find(|s: &&mut TcpSocket| match s.state {
                SockState::Connected { quad, .. } => quad == *search_quad,
                _ => false,
            })
            .or(tcp_listeners.find(|s| match s.state.port() {
                None => false,
                Some(p) => p == search_quad.dst.1 && s.listening(),
            }))
    }

    pub fn tcp_sockets<'a>(
        &'a self,
    ) -> FilterMap<Iter<'a, Socket>, impl FnMut(&'a Socket) -> Option<&'a TcpSocket>> {
        self.socks.iter().filter_map(|s| match s.sock {
            SocketKind::Tcp(ref s) => Some(s),
            _ => None,
        })
    }

    pub fn udp_sockets<'a>(
        &'a self,
    ) -> FilterMap<Iter<'a, Socket>, impl FnMut(&'a Socket) -> Option<&'a UdpSocket>> {
        self.socks.iter().filter_map(|s| match s.sock {
            SocketKind::Udp(ref s) => Some(s),
            _ => None,
        })
    }

    pub fn tcp_sockets_mut<'a>(
        &'a mut self,
    ) -> FilterMap<IterMut<'a, Socket>, impl FnMut(&'a mut Socket) -> Option<&'a mut TcpSocket>>
    {
        self.socks.iter_mut().filter_map(|s| match s.sock {
            SocketKind::Tcp(ref mut s) => Some(s),
            _ => None,
        })
    }

    pub fn udp_sockets_mut<'a>(
        &'a mut self,
    ) -> FilterMap<IterMut<'a, Socket>, impl FnMut(&'a mut Socket) -> Option<&'a mut UdpSocket>>
    {
        self.socks.iter_mut().filter_map(|s| match s.sock {
            SocketKind::Udp(ref mut s) => Some(s),
            _ => None,
        })
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

    let sock = match stype {
        SOCK_STREAM => SocketKind::Tcp(TcpSocket {
            fd,
            state: SockState::Unbound,
            stype: TcpType::TcpStream,
            recv_queue: Default::default(),
        }),
        SOCK_DGRAM => SocketKind::Udp(UdpSocket {
            state: SockState::Unbound,
            recv_queue: Default::default(),
        }),
        _ => return -EINVAL,
    };

    let sock = Socket { sock, fd };

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
    if addr.is_null() || (addrlen as usize) < mem::size_of::<sa_family_t>() {
        return -EINVAL;
    }

    let address = unsafe { *(addr as *const sockaddr_in) };
    let mut mgr = manager.unwrap_or(sockets()).lock().unwrap();
    let socket = mgr.get_sock(sockfd);

    if let Some(socket) = socket {
        let is_port_bound = match socket.sock {
            SocketKind::Tcp(_) => mgr.tcp_sockets().any(|s| match s.state.port() {
                Some(p) => p == address.sin_port,
                None => false,
            }),
            SocketKind::Udp(_) => mgr.udp_sockets().any(|s| match s.state.port() {
                Some(p) => p == address.sin_port,
                None => false,
            }),
        };

        if is_port_bound {
            return -EADDRINUSE;
        }

        let socket = mgr.get_sock(sockfd).unwrap();
        socket.sock.bind(addr, addrlen)
    } else {
        eprintln!("Unsupported socket type, binding to OS socket");
        unsafe { bind(sockfd, addr, addrlen) }
    }
}

fn get_highest_port<'a>(manager: &MutexGuard<'a, SocketManager>) -> u16 {
    manager.socks.iter().fold(1024, |acc, s| match &s.sock {
        SocketKind::Tcp(tcp) => {
            if let Some(port) = tcp.state.port() {
                if port > acc {
                    return port;
                }
            }

            return acc;
        }
        SocketKind::Udp(udp) => {
            if let Some(port) = udp.state.port() {
                if port > acc {
                    return port;
                }
            }

            return acc;
        }
    })
}

pub fn _listen(sockfd: i32, max_backlog: i32, manager: Option<&Mutex<SocketManager>>) -> i32 {
    let manager = manager.unwrap_or(sockets());
    let mut mgr = manager.lock().unwrap();
    let highest_port = get_highest_port(&mgr) + 1;

    let sock = mgr.get_sock(sockfd);

    if let Some(sock) = sock {
        sock.sock.listen(max_backlog, highest_port)
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
        let cur_fd = mgr.fd;
        let sock = mgr.get_sock(sockfd);

        if let Some(sock) = sock {
            match sock.sock.accept(addr, addrlen, cur_fd) {
                Ok(Some(new_sock)) => {
                    mgr.fd += 1;
                    mgr.stream_socks.push_back(Socket {
                        sock: new_sock,
                        fd: cur_fd,
                    });
                    return cur_fd;
                }
                Ok(None) => continue,
                Err(err) => return err,
            }
        } else {
            return unsafe { accept(sockfd, addr, addrlen) };
        }
    }
}

// ssize_t read(int sockfd, void *buf, size_t len);
// TODO: change the loop to wait for a condvar before reading from socket buffer again.
pub fn _read(sockfd: i32, buf: &mut Vec<u8>) -> isize {
    loop {
        let manager = sockets();
        let mut mgr = manager.lock().unwrap();
        let sock = mgr.get_sock(sockfd);

        if let Some(sock) = sock {
            match sock.sock.read(buf) {
                Some(nb) => return nb,
                None => continue,
            }
        } else {
            return unsafe { recv(sockfd, buf.as_slice().as_ptr() as *mut c_void, buf.len(), 0) };
        }
    }
}

pub fn _connect(
    sockfd: i32,
    addr: *const sockaddr,
    addrlen: socklen_t,
    manager: Option<&Mutex<SocketManager>>,
) -> i32 {
    unimplemented!()
}

#[cfg(test)]
mod socket_test {
    use std::{mem, sync::Mutex};

    use libc::{
        in_addr, sa_family_t, sockaddr, sockaddr_in, AF_INET, EADDRINUSE, EINVAL, ENOTSUP,
        SOCK_DGRAM, SOCK_STREAM,
    };

    use crate::socket::{SocketKind, TcpSocket, UdpSocket};

    use super::{SockState, SocketManager, TcpType, _bind, _listen, _socket};

    fn new_mgr() -> Mutex<SocketManager> {
        Mutex::new(SocketManager::default())
    }

    #[test]
    fn test_tcp_socket() {
        let mgr = new_mgr();
        let result = _socket(AF_INET, SOCK_STREAM, 0, Some(&mgr));
        let mgr = mgr.lock().unwrap();
        let sock = mgr.socks.front().expect("Expected socket to be created");

        assert_eq!(
            sock.sock,
            SocketKind::Tcp(TcpSocket {
                fd: 4097,
                recv_queue: Default::default(),
                state: SockState::Unbound,
                stype: TcpType::TcpStream,
            })
        );
        assert!(result > 0);
    }

    #[test]
    fn test_udp_socket() {
        let mgr = new_mgr();
        let result = _socket(AF_INET, SOCK_DGRAM, 0, Some(&mgr));
        let mgr = mgr.lock().unwrap();
        let sock = mgr.socks.front().expect("Expected socket to be created");

        assert_eq!(
            sock.sock,
            SocketKind::Udp(UdpSocket {
                state: SockState::Unbound,
                recv_queue: Default::default(),
            })
        );
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

        match sock.sock {
            SocketKind::Tcp(ref tcp) => {
                assert_eq!(tcp.state, SockState::Bound(8080));
            }
            SocketKind::Udp(_) => assert!(false, "Expected TCP socket"),
        }
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
