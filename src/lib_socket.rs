use libc::__errno_location;
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

    if response_header.kind == MessageKind::Error {
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
        drop(message);
        return -1;
    }

    let new_socket = Socket { fd: sockfd, libfd };
    socks.insert(sockfd, new_socket);

    sockfd
}
