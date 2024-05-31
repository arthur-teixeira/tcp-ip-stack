use libc::{__errno_location, c_void, size_t, sockaddr, sockaddr_in, socklen_t, ssize_t, EINVAL};
use std::{
    collections::HashMap,
    io::{Read, Write},
    os::unix::net::UnixStream,
    process::exit,
    sync::{Mutex, OnceLock, RwLock},
};
mod sock_types;

use sock_types::*;

fn sockets() -> &'static RwLock<HashMap<i32, Mutex<UnixStream>>> {
    static SOCKS: OnceLock<RwLock<HashMap<i32, Mutex<UnixStream>>>> = OnceLock::new();
    SOCKS.get_or_init(|| RwLock::new(HashMap::default()))
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

    let mut buf = [0; 512];
    let nb = match libfd.read(&mut buf) {
        Ok(nb) => nb,
        Err(e) => {
            eprintln!("Error reading IPC: {e:?}");
            return -1;
        }
    };

    let response_header = MessageHeader::read_from_buffer(&buf[..nb]);
    let response = ErrorMessage::read_from_buffer(&buf[MessageHeader::SIZE..nb]);

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
    let mut socks = sockets().write().unwrap();

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

    socks.insert(sockfd, Mutex::new(libfd));

    sockfd
}

#[no_mangle]
pub extern "C" fn socket_bind(sockfd: i32, addr: *const sockaddr, addrlen: socklen_t) -> i32 {
    if addr.is_null() {
        return -EINVAL;
    }

    let socks = sockets().read().unwrap();

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

    let mut lib_socket = match socks.get(&sockfd) {
        Some(s) => s,
        None => return -EINVAL, // TODO: call OS bind()
    }
    .lock()
    .unwrap();

    let mut buf = Vec::new();
    message.write_to_buffer(&mut buf);
    payload.write_to_buffer(&mut buf);

    send_to_nic(&mut lib_socket, &message, &buf)
}

#[no_mangle]
pub extern "C" fn socket_listen(sockfd: i32, backlog: i32) -> i32 {
    let socks = sockets().read().unwrap();

    let pid = std::process::id();
    let hdr = MessageHeader {
        kind: MessageKind::Listen,
        pid,
    };

    let payload = ListenMessage { sockfd, backlog };

    let mut lib_socket = match socks.get(&sockfd) {
        Some(s) => s,
        None => return -EINVAL, // TODO: call OS listen()
    }
    .lock()
    .unwrap();

    let mut buf = Vec::new();
    hdr.write_to_buffer(&mut buf);
    payload.write_to_buffer(&mut buf);

    send_to_nic(&mut lib_socket, &hdr, &buf)
}

#[no_mangle]
pub extern "C" fn socket_accept(sockfd: i32, addr: *mut sockaddr, addrlen: *mut socklen_t) -> i32 {
    let socks = sockets().read().unwrap();

    let pid = std::process::id();
    let hdr = MessageHeader {
        kind: MessageKind::Accept,
        pid,
    };

    let payload = AcceptMessage { sockfd };

    let mut lib_socket = match socks.get(&sockfd) {
        Some(s) => s,
        None => return -EINVAL, // TODO: call OS accept()
    }
    .lock()
    .unwrap();

    eprintln!("Using sockfd {} to accept connections", sockfd);

    let mut buf = Vec::new();
    hdr.write_to_buffer(&mut buf);
    payload.write_to_buffer(&mut buf);

    match lib_socket.write(&buf) {
        Ok(_) => {}
        Err(e) => eprintln!("Error writing IPC: {e:?}"),
    };

    let mut buf = [0; 512];
    match lib_socket.read(&mut buf) {
        Ok(nb) => nb,
        Err(e) => {
            eprintln!("Error reading IPC: {e:?}");
            return -1;
        }
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
        eprintln!("GOT HERE!");
        if addrlen.is_null() {
            return -EINVAL;
        }
        unsafe {
            std::ptr::copy(&response.addr, addr, std::mem::size_of::<sockaddr_in>());
            std::ptr::copy(&response.addrlen, addrlen, std::mem::size_of::<socklen_t>());
        }
    }

    let libfd = init_socket("/tmp/tcpip.socket");
    eprintln!("Accepted connection, creating new libsocket");

    drop(lib_socket);
    drop(socks);

    let mut socks = sockets().write().unwrap();
    eprintln!("Locked sockets, inserting in list");
    socks.insert(response.sockfd, Mutex::new(libfd));

    response.sockfd
}

#[no_mangle]
extern "C" fn socket_read(sockfd: i32, read_buf: *mut c_void, count: size_t) -> ssize_t {
    let socks = sockets().read().unwrap();

    eprintln!("Got read call!");
    let pid = std::process::id();
    let hdr = MessageHeader {
        kind: MessageKind::Read,
        pid,
    };

    let payload = ReadMessage { sockfd, count };

    let mut lib_socket = match socks.get(&sockfd) {
        Some(s) => s,
        None => return -(EINVAL as isize), // TODO: call OS read()
    }
    .lock()
    .unwrap();

    eprintln!("successfully acquired socket lock on sockfd: {}", sockfd);

    let mut buf = Vec::new();
    hdr.write_to_buffer(&mut buf);
    payload.write_to_buffer(&mut buf);

    match lib_socket.write(&buf) {
        Ok(_) => {}
        Err(e) => eprintln!("Error writing IPC: {e:?}"),
    };

    eprintln!("Waiting on ipc read");
    let mut buf = [0; 4096];
    match lib_socket.read(&mut buf) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Error reading IPC: {e:?}");
            return -1;
        }
    };
    eprintln!("ipc read successful");

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

    unsafe { std::ptr::copy_nonoverlapping(response.buf.as_ptr(), read_buf as *mut u8, count) }

    response.rc
}
