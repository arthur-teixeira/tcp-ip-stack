use libc::{__errno_location, c_void, size_t, sockaddr, socklen_t, ssize_t, EINVAL};
use std::{
    collections::HashMap,
    io::{Read, Write},
    os::unix::net::UnixStream,
    process::exit,
    sync::{Mutex, OnceLock},
};
mod sock_types;

use sock_types::*;

#[derive(Debug)]
struct Socket {
    libfd: UnixStream,
    fd: i32,
}

fn sockets() -> &'static Mutex<HashMap<i32, Socket>> {
    static SOCKS: OnceLock<Mutex<HashMap<i32, Socket>>> = OnceLock::new();
    SOCKS.get_or_init(|| Mutex::new(Default::default()))
}

fn init_socket(sockname: &str) -> UnixStream {
    let libsock = match UnixStream::connect(sockname) {
        Ok(sock) => sock,
        Err(e) => {
            eprintln!("Error initializing Socket: {e:?}. Is tcp-ip running?");
            exit(1);
        }
    };

    libsock
}

fn send_to_nic(libfd: &mut UnixStream, msg_hdr: &MessageHeader, msg: &[u8]) -> i32 {
    match libfd.write(msg) {
        Ok(_) => {}
        Err(e) => eprintln!("Error writing IPC: {e:?}"),
    };

    eprintln!("Message sent: {:?}", msg);

    let mut buf = [0; 512];
    match libfd.read(&mut buf) {
        Ok(_) => {}
        Err(e) => eprintln!("Error reading IPC: {e:?}"),
    };

    let response_header = MessageHeader::read_from_buffer(&buf);
    let response = ErrorMessage::read_from_buffer(&buf[MessageHeader::SIZE..]);

    if response.errno > 0 {
        unsafe { *__errno_location() = response.errno };
        return response.rc;
    }

    if response_header.kind != msg_hdr.kind || msg_hdr.pid != response_header.pid {
        eprintln!("Error on IPC Message response");
        return -1;
    }

    response.rc
}

#[no_mangle]
pub extern "C" fn socket_new(domain: i32, ptype: i32, protocol: i32) -> i32 {
    let mut libfd = init_socket("/tmp/tcpip.socket");
    let mut socks = sockets().lock().unwrap();

    let pid = std::process::id();
    let message = MessageHeader {
        kind: MessageKind::Socket,
        pid,
    };

    let payload = SocketMessage {
        ptype,
        domain,
        protocol,
    };

    let mut buf = Vec::new();
    message.write_to_buffer(&mut buf);
    payload.write_to_buffer(&mut buf);

    let sockfd = send_to_nic(&mut libfd, &message, &buf);

    if sockfd < 0 {
        return -1;
    }

    let new_socket = Socket { fd: sockfd, libfd };
    socks.insert(sockfd, new_socket);

    sockfd
}

#[no_mangle]
pub extern "C" fn socket_bind(sockfd: i32, addr: *const sockaddr, addrlen: socklen_t) -> i32 {
    if addr.is_null() {
        return -EINVAL;
    }

    let mut socks = sockets().lock().unwrap();

    let pid = std::process::id();
    let message = MessageHeader {
        kind: MessageKind::Bind,
        pid,
    };

    let payload = BindMessage {
        sockfd,
        addrlen,
        addr: unsafe { *addr },
    };

    let lib_socket = match socks.get_mut(&sockfd) {
        Some(s) => s,
        None => return -EINVAL, // TODO: call OS bind()
    };

    let mut buf = Vec::new();
    message.write_to_buffer(&mut buf);
    payload.write_to_buffer(&mut buf);

    send_to_nic(&mut lib_socket.libfd, &message, &buf)
}

#[no_mangle]
pub extern "C" fn socket_listen(sockfd: i32, backlog: i32) -> i32 {
    let mut socks = sockets().lock().unwrap();

    let pid = std::process::id();
    let hdr = MessageHeader {
        kind: MessageKind::Listen,
        pid,
    };

    let payload = ListenMessage { sockfd, backlog };

    let lib_socket = match socks.get_mut(&sockfd) {
        Some(s) => s,
        None => return -EINVAL, // TODO: call OS listen()
    };

    let mut buf = Vec::new();
    hdr.write_to_buffer(&mut buf);
    payload.write_to_buffer(&mut buf);

    send_to_nic(&mut lib_socket.libfd, &hdr, &buf)
}

#[no_mangle]
pub extern "C" fn socket_accept(sockfd: i32, addr: *mut sockaddr, addrlen: *mut socklen_t) -> i32 {
    let mut socks = sockets().lock().unwrap();

    let pid = std::process::id();
    let hdr = MessageHeader {
        kind: MessageKind::Accept,
        pid,
    };

    let payload = AcceptMessage { sockfd };

    let lib_socket = match socks.get_mut(&sockfd) {
        Some(s) => s,
        None => return -EINVAL, // TODO: call OS accept()
    };

    let mut buf = Vec::new();
    hdr.write_to_buffer(&mut buf);
    payload.write_to_buffer(&mut buf);

    match lib_socket.libfd.write(&buf) {
        Ok(_) => {}
        Err(e) => eprintln!("Error writing IPC: {e:?}"),
    };

    eprintln!("Message sent: {:?}", &buf);

    let mut buf = [0; 512];
    match lib_socket.libfd.read(&mut buf) {
        Ok(_) => {}
        Err(e) => eprintln!("Error reading IPC: {e:?}"),
    };

    let response_header = MessageHeader::read_from_buffer(&buf);
    let response = AcceptResponse::read_from_buffer(&buf[MessageHeader::SIZE..]);

    if response.errno > 0 {
        unsafe { *__errno_location() = response.errno };
        return response.sockfd;
    }

    if response_header.kind != hdr.kind || hdr.pid != response_header.pid {
        eprintln!("Error on IPC Message response");
        return -1;
    }

    if !addr.is_null() {
        if addrlen.is_null() {
            return -EINVAL;
        }
        unsafe {
            *addr = response.addr;
            *addrlen = response.addrlen;
        }
    }

    response.sockfd
}

#[no_mangle]
extern "C" fn socket_read(sockfd: i32, read_buf: *mut c_void, count: size_t) -> ssize_t {
    let mut socks = sockets().lock().unwrap();

    let pid = std::process::id();
    let hdr = MessageHeader {
        kind: MessageKind::Accept,
        pid,
    };

    let payload = ReadMessage { sockfd, count };

    let lib_socket = match socks.get_mut(&sockfd) {
        Some(s) => s,
        None => return -(EINVAL as isize), // TODO: call OS read()
    };

    let mut buf = Vec::new();
    hdr.write_to_buffer(&mut buf);
    payload.write_to_buffer(&mut buf);

    match lib_socket.libfd.write(&buf) {
        Ok(_) => {}
        Err(e) => eprintln!("Error writing IPC: {e:?}"),
    };

    let mut buf = Vec::with_capacity(512 + count);
    match lib_socket.libfd.read(&mut buf) {
        Ok(_) => {}
        Err(e) => eprintln!("Error reading IPC: {e:?}"),
    };

    let response_header = MessageHeader::read_from_buffer(&buf);
    let response = ReadResponse::read_from_buffer(&buf[MessageHeader::SIZE..]);
    if response.errno > 0 {
        unsafe { *__errno_location() = response.errno };
        return response.rc;
    }

    if response_header.kind != hdr.kind || hdr.pid != response_header.pid {
        eprintln!("Error on IPC Message response");
        return -1;
    }

    unsafe { std::ptr::copy(&response.buf, read_buf as *mut _, count) }

    response.rc
}
