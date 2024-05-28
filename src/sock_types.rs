use libc::c_int;
use std::mem::ManuallyDrop;

#[repr(C)]
#[derive(PartialEq, Eq)]
pub enum MessageKind {
    Socket,
    Bind,
    Listen,
    Accept,
    Read,
    Write,
    Error,
}

#[repr(C, packed)]
#[derive(PartialEq, Eq, Debug)]
pub struct SocketMessage {
   pub domain: c_int,
   pub ptype: c_int,
   pub protocol: c_int,
}

#[repr(C, packed)]
pub struct ErrorMessage {
   pub errno: i32,
   pub rc: i32,
}

#[repr(C, packed)]
pub union MessagePayload {
   pub socket: ManuallyDrop<SocketMessage>,
   pub error: ManuallyDrop<ErrorMessage>,
}

#[repr(C, packed)]
pub struct Message {
   pub kind: MessageKind,
   pub pid: u32,
   pub payload: MessagePayload,
}
