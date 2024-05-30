use std::{
    io::{Read, Result, Write},
    os::unix::net::{UnixListener, UnixStream},
    process::exit,
    thread::JoinHandle,
};

use crate::{
    sock_types::*,
    socket::{_accept, _bind, _listen, _read, _socket},
};

use libc::{sockaddr, socklen_t};

pub fn start_ipc_listener() -> JoinHandle<()> {
    std::thread::spawn(move || {
        let sockname = "/tmp/tcpip.socket";
        let _ = std::fs::remove_file(sockname);

        let sock = UnixListener::bind(sockname)
            .map_err(|e| {
                eprintln!("Error creating IPC listener: {e:?}");
                exit(1);
            })
            .unwrap();

        loop {
            let (mut stream, _addr) = sock
                .accept()
                .map_err(|e| {
                    eprintln!("Could not accept connection: {e:?}");
                    exit(1);
                })
                .unwrap();

            let reactor_handle = std::thread::spawn(move || {
                let mut buf = [0; 8192];
                'reactor: loop {
                    let nb = match stream.read(&mut buf) {
                        Ok(nb) => nb,
                        Err(e) => {
                            eprintln!("Error reading from ipc socket: {e:?}");
                            break 'reactor;
                        }
                    };
                    if nb == 0 {
                        break 'reactor;
                    }

                    match process_ipc_call(&mut stream, &buf[..nb]) {
                        Ok(nb) => {
                            eprintln!("Successfully sent message of {nb} bytes");
                        }
                        Err(e) => {
                            eprintln!("Error processing IPC call: {e:?}");
                            break 'reactor;
                        }
                    }
                }
            });

            reactor_handle
                .join()
                .expect("Expected to join reactor thread");

            // TODO: Close connection and drop socket here
        }
    })
}

fn process_ipc_call(stream: &mut UnixStream, msg: &[u8]) -> Result<usize> {
    let hdr: MessageHeader = MessageHeader::read_from_buffer(&msg);
    eprintln!("Message received: {:?}", hdr.kind);

    match hdr.kind {
        MessageKind::Socket => process_socket_call(stream, msg),
        MessageKind::Bind => process_bind_call(stream, msg),
        MessageKind::Listen => process_listen_call(stream, msg),
        MessageKind::Accept => process_accept_call(stream, msg),
        MessageKind::Read => process_read_call(stream, msg),
        MessageKind::Write => todo!(),
        MessageKind::Error => todo!(),
    }
}

fn write_response(result: i32, stream: &mut UnixStream, msg: &[u8]) -> Result<usize> {
    let errno = if result < 0 { -result } else { 0 };

    let response_header = MessageHeader::read_from_buffer(msg);
    let response_message = ErrorMessage { errno, rc: result };

    let mut buf = Vec::new();
    response_header.write_to_buffer(&mut buf);
    response_message.write_to_buffer(&mut buf);

    stream.write(&buf)
}

fn process_socket_call(stream: &mut UnixStream, msg: &[u8]) -> Result<usize> {
    let payload = SocketMessage::read_from_buffer(&msg[MessageHeader::SIZE..]);

    let sockfd = _socket(payload.domain, payload.ptype, payload.protocol, None);
    write_response(sockfd, stream, msg)
}

fn process_bind_call(stream: &mut UnixStream, msg: &[u8]) -> Result<usize> {
    let payload = BindMessage::read_from_buffer(&msg[MessageHeader::SIZE..]);

    let result = _bind(
        payload.sockfd,
        &payload.addr as *const _,
        payload.addrlen,
        None,
    );
    write_response(result, stream, msg)
}

fn process_listen_call(stream: &mut UnixStream, msg: &[u8]) -> Result<usize> {
    let payload = ListenMessage::read_from_buffer(&msg[MessageHeader::SIZE..]);

    let result = _listen(payload.sockfd, payload.backlog, None);
    write_response(result, stream, msg)
}

fn process_accept_call(stream: &mut UnixStream, msg: &[u8]) -> Result<usize> {
    let payload = AcceptMessage::read_from_buffer(&msg[MessageHeader::SIZE..]);

    let mut addr: sockaddr = sockaddr {
        sa_family: 1,
        sa_data: [0; 14],
    };

    let mut addrlen: socklen_t = 0;

    let result = _accept(payload.sockfd, &mut addr, &mut addrlen, None);

    let errno = if result < 0 { -result } else { 0 };

    let response_header = MessageHeader::read_from_buffer(msg);
    let response_message = AcceptResponse {
        sockfd: result,
        errno,
        addr,
        addrlen,
    };

    let mut buf = Vec::new();
    response_header.write_to_buffer(&mut buf);
    response_message.write_to_buffer(&mut buf);

    stream.write(&buf)
}

fn process_read_call(stream: &mut UnixStream, msg: &[u8]) -> Result<usize> {
    let payload = ReadMessage::read_from_buffer(&msg[MessageHeader::SIZE..]);

    let mut buf = Vec::with_capacity(payload.count);
    let result = _read(payload.sockfd, &mut buf);

    let errno = if result < 0 { -result } else { 0 } as i32;

    let response_header = MessageHeader::read_from_buffer(msg);
    let response_message = ReadResponse {
        errno,
        rc: result,
        buf: buf.into_boxed_slice(),
    };

    let mut response_buf = Vec::new();
    response_header.write_to_buffer(&mut response_buf);
    response_message.write_to_buffer(&mut response_buf);

    stream.write(&response_buf)
}
