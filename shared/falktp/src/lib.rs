//! Falk transfer protocol

#![no_std]

extern crate alloc;

use alloc::borrow::Cow;
use noodle::*;

noodle!(serialize, deserialize,
/// Messages sent to and from the server for network mapped files
#[derive(Debug)]
pub enum ServerMessage<'a> {
    /// Request a file ID for a filename on the server. This will cause the
    /// file to get loaded into memory on the server and persisted with the
    /// same ID.
    GetFileId(Cow<'a, str>),

    /// If getting the file ID failed, this will be sent back by the server
    FileIdErr,

    /// Returns the file ID and length of the requested filename from a
    /// `GetFileId()` if the file exists on the server
    FileId {
        /// File ID
        id: u64,

        /// Size of the file (in bytes)
        size: usize,
    },

    /// Request a read of an opened file
    Read {
        /// File identifier from a successful `OpenRequest`
        id: u64,

        /// Offset (in bytes) into the file to request to read
        offset: usize,

        /// Size (in bytes) to request
        size: usize,
    },

    /// Indicates that the read is valid, and there are UDP frames following
    /// this packet containing the raw bytes for the `size` requested.
    ReadOk,

    /// Indicates that reading the file failed
    ReadErr,

    CovUpdate {
        total_length: u64,
        offset: u64,
        chunk: Cow<'a, [u64]>,
    }
});

