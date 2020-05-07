//! Implementation of the falktp transfer protocol

#[allow(unused)]
#[macro_use] extern crate noodle;

use std::io;
use std::path::Path;
use std::time::SystemTime;
use std::hash::{Hash, Hasher};
use std::net::UdpSocket;
use std::collections::{HashMap, BTreeSet};
use std::collections::hash_map::DefaultHasher;

use noodle::*;
use falktp::{ServerMessage, NodeResult, Checksum};

/// If `true` prints some extra spew
const VERBOSE: bool = true;

fn write_corpus(inp: &[u8]) {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.input(inp);
    let hash = hasher.result();
    std::fs::write(format!("/tmp/corpus/{:#x}.bin", hash), inp).unwrap()
}

fn main() -> io::Result<()> {
    // Map from file IDs to the modified time and their contents
    let mut file_db: HashMap<u64, (SystemTime, Vec<u8>)> = HashMap::new();

    // Get the current directory
    let cur_dir = std::fs::canonicalize("files")?;

    // Bind to all network devices on UDP port 1911
    let socket = UdpSocket::bind("0.0.0.0:1911")?;

    // Buffer for sending packets (reused to prevent allocations)
    let mut sendbuf = Vec::new();

    let mut coverage_db = BTreeSet::new();

    loop {
        // Read a UDP packet from the network
        let mut buf = [0; 2048];
        let (amt, src) = socket.recv_from(&mut buf)?;
        let mut ptr = &buf[..amt];

        // Deserialize the message
        let msg = ServerMessage::deserialize(&mut ptr)
            .expect("Failed to deserialize ServerMessage");

        match msg {
            ServerMessage::GetFileId(filename) => {
                // Normalize the filename
                if let Ok(filename) =
                        std::fs::canonicalize(Path::new("files")
                                              .join(&*filename)) {
                    // Jail the filename to the current directory
                    if !filename.starts_with(&cur_dir) {
                        // Send the file error response
                        sendbuf.clear();
                        ServerMessage::FileIdErr.serialize(
                            &mut sendbuf).unwrap();
                        socket.send_to(&sendbuf, src)?;
                        continue;
                    }

                    // Compute the file ID by hashing the file path
                    let mut hasher = DefaultHasher::new();
                    filename.to_str().unwrap().hash(&mut hasher);
                    let file_id = hasher.finish();

                    // Get the modified time of the file
                    let modified = filename.metadata().unwrap()
                        .modified().unwrap();

                    // Insert into the file database if needed
                    let file = file_db.entry(file_id)
                        .or_insert_with(|| {
                            print!("Loading {:?}\n", filename);
                            (modified, std::fs::read(&filename).unwrap())
                        });

                    // Check if we should reload the file since it has been
                    // modified
                    if file.0 < modified {
                        print!("Reloading {:?}\n", filename);
                        *file = (modified, std::fs::read(&filename).unwrap());
                    }

                    // Send the ID response
                    sendbuf.clear();
                    ServerMessage::FileId {
                        id:   file_id,
                        size: file.1.len(),
                    }.serialize(&mut sendbuf).unwrap();
                    socket.send_to(&sendbuf, src)?;
                } else {
                    // Send the file error response
                    sendbuf.clear();
                    ServerMessage::FileIdErr.serialize(&mut sendbuf).unwrap();
                    socket.send_to(&sendbuf, src)?;
                }
            },
            ServerMessage::Read { id, offset, size } => {
                if VERBOSE {
                    print!("Read {:016x} offset {} for {}\n",
                           id, offset, size);
                }

                // Attempt to get access to the file contents at the requested
                // location
                let sliced = file_db.get(&id).and_then(|(_, x)| {
                    x.get(offset..offset + size)
                });

                if let Some(sliced) = sliced {
                    let checksum = Checksum::compute(sliced);
                    sendbuf.clear();
                    ServerMessage::ReadOk {
                        id,
                        offset,
                        size,
                        checksum,
                    }
                        .serialize(&mut sendbuf).unwrap();
                    socket.send_to(&sendbuf, src)?;

                    // Send the contents
                    for chunk in sliced.chunks(1472) {
                        socket.send_to(chunk, src)?;
                    }
                } else {
                    sendbuf.clear();
                    ServerMessage::ReadErr.serialize(&mut sendbuf).unwrap();
                    socket.send_to(&sendbuf, src)?;
                }
            },
            ServerMessage::CovUpdate {
                total_length,
                offset,
                chunk
            } => {
                if offset == 0 {
                    coverage_db.clear();
                }
                for &entry in chunk.iter() {
                    coverage_db.insert(entry);
                }
                if coverage_db.len() as u64 == total_length {
                    print!("recv'd coverage update {} entries\n", total_length);
                }

                use std::io::Write;
                let mut f = std::fs::File::create("/tmp/coverage_log").unwrap();
                f.write_all(b"rip_u64\n").unwrap();
                for &entry in &coverage_db {
                    f.write_all(&u64::to_le_bytes(entry)).unwrap();
                }
            }
            ServerMessage::SlightlyLossyTransport {
                uuid,
                length,
                checksum,
                offset,
                chunk
            } => {
                println!("SLT: {:#x}, {}/{}", uuid, offset, length);
                if chunk.len() < length { panic!("TODO: large path"); }
                let data = chunk.iter().copied().collect::<Vec<_>>();
                checksum.assert_eq(&data);
                // Deserialize the message
                let res = NodeResult::deserialize(&mut &data[..])
                    .expect("Failed to deserialize NodeResult");
                println!("{:?}", res);
                match res {
                    NodeResult::UniqueExit(reason, input) => write_corpus(&input),
                    NodeResult::NewInput(input) => write_corpus(&input),
                    _ => {}
                }
            }
            x @ _ => panic!("Unhandled packet {:#?}\n", x),
        }
    }
}

