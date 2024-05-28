use libc::__errno_location;
use std::{
    collections::HashMap,
    io::{Read, Write},
    mem::ManuallyDrop,
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

pub fn sockets() -> &'static Mutex<HashMap<i32, Socket>> {
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

unsafe fn struct_to_bytes<T: Sized>(p: &T) -> &[u8] {
    core::slice::from_raw_parts((p as *const T) as *const u8, core::mem::size_of::<T>())
}

fn send_to_nic(libfd: &mut UnixStream, msg: &Message) -> i32 {
    match libfd.write(unsafe { struct_to_bytes(&msg) }) {
        Ok(_) => {}
        Err(e) => eprintln!("Error writing IPC: {e:?}"),
    };

    let mut buf = [0; 512];
    match libfd.read(&mut buf) {
        Ok(_) => {}
        Err(e) => eprintln!("Error reading IPC: {e:?}"),
    };

    let response: Message = unsafe { std::ptr::read(buf.as_ptr() as *const _) };

    let kind_addr = std::ptr::addr_of!(response.kind);
    let msg_kind_addr = std::ptr::addr_of!(msg.kind);

    unsafe {
        if std::ptr::read(kind_addr) == MessageKind::Error {
            *__errno_location() = response.payload.error.errno;
            return response.payload.error.rc;
        }
    }

    if unsafe { std::ptr::read_unaligned(kind_addr) != std::ptr::read_unaligned(msg_kind_addr) }
        || response.pid != msg.pid
    {
        eprintln!("Error on IPC Message response");
        return -1;
    }

    unsafe { response.payload.error.rc }
}

#[no_mangle]
pub extern "C" fn socket_new(domain: i32, ptype: i32, protocol: i32) -> i32 {
    let mut libfd = init_socket("/tmp/tcpip.socket");
    let mut socks = sockets().lock().unwrap();

    let pid = std::process::id();
    let message = Message {
        kind: MessageKind::Socket,
        pid,
        payload: MessagePayload {
            socket: ManuallyDrop::new(SocketMessage {
                ptype,
                domain,
                protocol,
            }),
        },
    };

    let sockfd = send_to_nic(&mut libfd, &message);

    if sockfd < 0 {
        drop(message);
        return -1;
    }

    let new_socket = Socket { fd: sockfd, libfd };
    println!("Socket called, {:?}", new_socket);
    socks.insert(sockfd, new_socket);

    sockfd
}
