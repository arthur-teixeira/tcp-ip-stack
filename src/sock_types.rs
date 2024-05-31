use libc::{c_int, size_t, sockaddr, socklen_t, wait};
use std::fmt::Debug;

#[repr(u8)]
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum MessageKind {
    Socket,
    Bind,
    Listen,
    Accept,
    Read,
    Write,
    Error,
}

impl MessageKind {
    pub fn from_u8(n: u8) -> Self {
        match n {
            0 => Self::Socket,
            1 => Self::Bind,
            2 => Self::Listen,
            3 => Self::Accept,
            4 => Self::Read,
            5 => Self::Write,
            6 => Self::Error,
            _ => panic!("Invalid message kind: {}", n),
        }
    }
}

pub trait WriteToBuffer {
    fn write_to_buffer(&self, buffer: &mut Vec<u8>);
}

pub trait ReadFromBuffer {
    fn read_from_buffer(buffer: &[u8]) -> Self;
}

#[repr(C)]
#[derive(PartialEq, Eq, Debug)]
pub struct SocketMessage {
    pub domain: c_int,
    pub ptype: c_int,
    pub protocol: c_int,
}
impl WriteToBuffer for SocketMessage {
    fn write_to_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend(self.domain.to_be_bytes());
        buffer.extend(self.ptype.to_be_bytes());
        buffer.extend(self.protocol.to_be_bytes());
    }
}
impl ReadFromBuffer for SocketMessage {
    fn read_from_buffer(buffer: &[u8]) -> Self {
        let mut buf = [0; 4];
        buf.copy_from_slice(&buffer[..=3]);
        let domain = c_int::from_be_bytes(buf);

        buf.copy_from_slice(&buffer[4..=7]);
        let ptype = c_int::from_be_bytes(buf);

        buf.copy_from_slice(&buffer[8..=11]);
        let protocol = c_int::from_be_bytes(buf);

        Self {
            domain,
            ptype,
            protocol,
        }
    }
}

#[repr(C)]
pub struct BindMessage {
    pub sockfd: i32,
    pub addrlen: socklen_t,
    pub addr: sockaddr,
}

impl Debug for BindMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BindMessage {{\n \t sockfd: {},\n\t addrlen:{}\n}}",
            self.sockfd, self.addrlen
        )
    }
}

impl ReadFromBuffer for BindMessage {
    fn read_from_buffer(buffer: &[u8]) -> Self {
        let mut buf = [0; 4];
        buf.copy_from_slice(&buffer[..=3]);
        let sockfd = c_int::from_be_bytes(buf);

        buf.copy_from_slice(&buffer[4..=7]);
        let addrlen = socklen_t::from_be_bytes(buf);

        let addr: sockaddr = unsafe { std::ptr::read(buffer[8..].as_ptr() as *const _) };

        Self {
            sockfd,
            addrlen,
            addr,
        }
    }
}

fn struct_to_bytes<T: Sized>(p: &T) -> &[u8] {
    unsafe { core::slice::from_raw_parts((p as *const T) as *const u8, core::mem::size_of::<T>()) }
}

impl WriteToBuffer for BindMessage {
    fn write_to_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend(self.sockfd.to_be_bytes());
        buffer.extend(self.addrlen.to_be_bytes());
        let addr = struct_to_bytes(&self.addr);
        assert_eq!(self.addrlen as usize, addr.len());
        buffer.extend(addr);
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct ListenMessage {
    pub sockfd: i32,
    pub backlog: i32,
}

impl WriteToBuffer for ListenMessage {
    fn write_to_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend(self.sockfd.to_be_bytes());
        buffer.extend(self.backlog.to_be_bytes());
    }
}

impl ReadFromBuffer for ListenMessage {
    fn read_from_buffer(buffer: &[u8]) -> Self {
        let mut buf = [0; 4];
        buf.copy_from_slice(&buffer[0..=3]);
        let sockfd = i32::from_be_bytes(buf);

        buf.copy_from_slice(&buffer[4..=7]);
        let backlog = i32::from_be_bytes(buf);

        Self { sockfd, backlog }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct AcceptMessage {
    pub sockfd: i32,
}

impl WriteToBuffer for AcceptMessage {
    fn write_to_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend(self.sockfd.to_be_bytes());
    }
}

impl ReadFromBuffer for AcceptMessage {
    fn read_from_buffer(buffer: &[u8]) -> Self {
        let mut buf = [0; 4];
        buf.copy_from_slice(&buffer[0..=3]);
        let sockfd = i32::from_be_bytes(buf);

        Self { sockfd }
    }
}
#[repr(C)]
pub struct AcceptResponse {
    pub sockfd: i32,
    pub errno: i32,
    pub addrlen: socklen_t,
    pub addr: sockaddr,
}

impl WriteToBuffer for AcceptResponse {
    fn write_to_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend(self.sockfd.to_be_bytes());
        buffer.extend(self.errno.to_be_bytes());
        buffer.extend(self.addrlen.to_be_bytes());
        let addr = struct_to_bytes(&self.addr);
        buffer.extend(addr);
    }
}

impl ReadFromBuffer for AcceptResponse {
    fn read_from_buffer(buffer: &[u8]) -> Self {
        let mut buf = [0; 4];
        buf.copy_from_slice(&buffer[0..=3]);
        let sockfd = i32::from_be_bytes(buf);

        buf.copy_from_slice(&buffer[4..=7]);
        let errno = i32::from_be_bytes(buf);

        buf.copy_from_slice(&buffer[8..=11]);
        let addrlen = socklen_t::from_be_bytes(buf);

        let addr: sockaddr = unsafe { std::ptr::read(buffer[12..].as_ptr() as *const _) };

        Self {
            sockfd,
            errno,
            addrlen,
            addr,
        }
    }
}

#[repr(C)]
pub struct ReadMessage {
    pub sockfd: i32,
    pub count: size_t,
}

impl WriteToBuffer for ReadMessage {
    fn write_to_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.sockfd.to_be_bytes());
        buffer.extend_from_slice(&self.count.to_be_bytes());
    }
}

impl ReadFromBuffer for ReadMessage {
    fn read_from_buffer(buffer: &[u8]) -> Self {
        let mut sockfd_buf = [0; 4];
        sockfd_buf.copy_from_slice(&buffer[0..=3]);
        let sockfd = i32::from_be_bytes(sockfd_buf);

        let mut count_buf = [0; 8];
        count_buf.copy_from_slice(&buffer[4..=11]);
        let count = size_t::from_be_bytes(count_buf);

        Self { sockfd, count }
    }
}

#[repr(C)]
pub struct ReadResponse {
    pub errno: i32,
    pub rc: isize,
    pub buf: Box<[u8]>,
}

impl WriteToBuffer for ReadResponse {
    fn write_to_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend(self.errno.to_be_bytes());
        buffer.extend(self.rc.to_be_bytes());
        buffer.extend_from_slice(&self.buf);
    }
}

impl ReadFromBuffer for ReadResponse {
    fn read_from_buffer(buffer: &[u8]) -> ReadResponse {
        let mut buf = [0; 4];
        buf.copy_from_slice(&buffer[..=3]);
        let errno = i32::from_be_bytes(buf);

        let mut buf = [0; 8];
        buf.copy_from_slice(&buffer[4..=11]);
        let rc = isize::from_be_bytes(buf);

        Self {
            errno,
            rc,
            buf: buffer[12..].into(),
        }
    }
}

#[repr(C)]
#[derive(PartialEq, Eq, Debug)]
pub struct ErrorMessage {
    pub errno: i32,
    pub rc: i32,
}

impl WriteToBuffer for ErrorMessage {
    fn write_to_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend(self.errno.to_be_bytes());
        buffer.extend(self.rc.to_be_bytes());
    }
}
impl ReadFromBuffer for ErrorMessage {
    fn read_from_buffer(buffer: &[u8]) -> Self {
        let mut buf = [0; 4];
        buf.copy_from_slice(&buffer[..=3]);
        let errno = i32::from_be_bytes(buf);

        buf.copy_from_slice(&buffer[4..=7]);
        let rc = i32::from_be_bytes(buf);

        Self { errno, rc }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct MessageHeader {
    pub kind: MessageKind,
    pub pid: u32,
}

impl MessageHeader {
    pub const SIZE: usize = 5;
}

impl WriteToBuffer for MessageHeader {
    fn write_to_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.push(self.kind as u8);
        buffer.extend(self.pid.to_be_bytes());
    }
}

impl ReadFromBuffer for MessageHeader {
    fn read_from_buffer(buffer: &[u8]) -> Self {
        let kind = MessageKind::from_u8(buffer[0]);

        let mut buf = [0; 4];
        buf.copy_from_slice(&buffer[1..=4]);
        let pid = u32::from_be_bytes(buf);

        Self { kind, pid }
    }
}
