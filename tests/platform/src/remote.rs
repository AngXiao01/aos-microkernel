//! Host side of the storage protocol: a [`LogStorage`] over the virtio-console socket.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use aos_log::LogStorage;
use aos_storage::wire::{self, Frame, Stat};

#[derive(Debug, PartialEq, Eq)]
pub struct RemoteError(pub String);

struct Conn {
    sock: UnixStream,
    buf: Vec<u8>,
}

impl Conn {
    fn rpc(&mut self, op: u16, body: &[u8]) -> Frame {
        let frame = Frame::request(op, 1, body.to_vec());
        self.sock.write_all(&frame.encode()).expect("write to guest");
        loop {
            match wire::decode(&mut self.buf) {
                Ok(Some(frame)) => return frame,
                Ok(None) => {
                    let mut tmp = [0u8; 4096];
                    let n = self.sock.read(&mut tmp).expect("read from guest");
                    if n == 0 {
                        panic!("guest closed the console");
                    }
                    self.buf.extend_from_slice(&tmp[..n]);
                }
                Err(e) => panic!("bad frame from guest: {e:?}"),
            }
        }
    }
}

/// Live connection, or a snapshot of entries fetched from one (for replay).
pub struct Remote {
    conn: Option<Mutex<Conn>>,
    entries: Vec<Vec<u8>>,
}

impl Remote {
    pub fn connect(path: &Path) -> Remote {
        let mut last = None;
        for _ in 0..100 {
            match UnixStream::connect(path) {
                Ok(sock) => {
                    sock.set_read_timeout(Some(Duration::from_secs(8))).ok();
                    sock.set_write_timeout(Some(Duration::from_secs(8))).ok();
                    let mut conn = Conn { sock, buf: Vec::new() };
                    let hello = conn.rpc(wire::OP_HELLO, &[]);
                    assert_eq!(hello.status, wire::ST_OK, "HELLO status {}", hello.status);
                    let stat = Stat::decode(&hello.body).expect("HELLO body");
                    let mut remote = Remote { conn: Some(Mutex::new(conn)), entries: Vec::new() };
                    if stat.fault == 0 {
                        let n = stat.entries;
                        for seq in 0..n {
                            let body = seq.to_le_bytes().to_vec();
                            let reply = remote.rpc(wire::OP_READ, &body);
                            assert_eq!(reply.status, wire::ST_OK, "READ {seq} status {}", reply.status);
                            remote.entries.push(reply.body);
                        }
                    }
                    let _ = stat;
                    return remote;
                }
                Err(e) => last = Some(e),
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("cannot connect to {}: {last:?}", path.display());
    }

    pub fn entries(&self) -> &[Vec<u8>] {
        &self.entries
    }

    pub fn stat(&self) -> Stat {
        let reply = self.rpc(wire::OP_STAT, &[]);
        assert_eq!(reply.status, wire::ST_OK);
        Stat::decode(&reply.body).expect("STAT body")
    }

    pub fn arm_halt(&self) {
        let reply = self.rpc(wire::OP_ARM_HALT, &[]);
        assert_eq!(reply.status, wire::ST_OK);
    }

    pub fn shutdown(&self) {
        let reply = self.rpc(wire::OP_SHUTDOWN, &[]);
        assert_eq!(reply.status, wire::ST_OK);
    }

    /// Appends raw entry bytes and returns the status word (used by BS5).
    pub fn append_raw(&mut self, bytes: &[u8]) -> u16 {
        let reply = self.rpc(wire::OP_APPEND, bytes);
        if reply.status == wire::ST_OK {
            self.entries.push(bytes.to_vec());
        }
        reply.status
    }

    fn rpc(&self, op: u16, body: &[u8]) -> Frame {
        self.conn.as_ref().expect("snapshot has no connection").lock().expect("conn").rpc(op, body)
    }
}

impl Clone for Remote {
    fn clone(&self) -> Remote {
        // Replay reads the bytes the guest returns, not the host's cache.
        let n = if self.conn.is_some() {
            let reply = self.rpc(wire::OP_LEN, &[]);
            assert_eq!(reply.status, wire::ST_OK);
            u64::from_le_bytes(reply.body[..8].try_into().unwrap())
        } else {
            self.entries.len() as u64
        };
        let mut entries = Vec::with_capacity(n as usize);
        for seq in 0..n {
            if self.conn.is_some() {
                let reply = self.rpc(wire::OP_READ, &seq.to_le_bytes());
                assert_eq!(reply.status, wire::ST_OK, "replay READ {seq}");
                entries.push(reply.body);
            } else {
                entries.push(self.entries[seq as usize].clone());
            }
        }
        Remote { conn: None, entries }
    }
}

impl LogStorage for Remote {
    type Error = RemoteError;

    fn append(&mut self, entry: &[u8]) -> Result<(), RemoteError> {
        let status = self.append_raw(entry);
        if status == wire::ST_OK { Ok(()) } else { Err(RemoteError(format!("append status {status}"))) }
    }

    fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    fn read(&self, seq: u64) -> Result<Vec<u8>, RemoteError> {
        self.entries.get(seq as usize).cloned().ok_or(RemoteError(format!("no entry {seq}")))
    }
}
