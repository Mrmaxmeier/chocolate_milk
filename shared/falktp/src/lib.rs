//! Falk transfer protocol

#![no_std]

extern crate alloc;

use alloc::borrow::Cow;
use noodle::*;


noodle!(serialize, deserialize,
    #[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
    pub struct Checksum(u16);
);

impl Checksum {
    pub fn compute(data: &[u8]) -> Self {
        let mut sum1 = 0xab_u16;
        let mut sum2 = 0xcd_u16;
        for &c in data {
            sum1 = sum1.wrapping_add(c as u16);
            sum2 = sum2.wrapping_add(sum1);
        }
        Checksum(sum2)
    }
    pub fn matches(&self, data: &[u8]) -> bool {
        *self == Checksum::compute(data)
    }
    pub fn assert_eq(&self, data: &[u8]) {
        assert!(self.matches(data), "Checksum mismatch!");
    }
}


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
    ReadOk {
        /// Requested file id
        id: u64,

        /// Requested offset
        offset: usize,

        /// Requested size
        size: usize,

        /// Checksum of the requested chunk
        checksum: Checksum
    },

    /// Indicates that reading the file failed
    ReadErr,

    PollExplore,
    Explore { epoch: u64, rip: Option<u64> },
    CovUpdate {
        total_length: u64,
        offset: u64,
        chunk: Cow<'a, [u64]>,
    },
    SlightlyLossyTransport {
        uuid: u64,
        length: usize,
        checksum: Checksum,
        offset: u64,
        chunk: Cow<'a, [u8]>
    }
});


noodle!(serialize, deserialize,
    #[derive(Debug)]
    pub struct Statistics {
        uuid: u64,
        fuzz_cases: u64,
        coverage: u64,
        corpus_len: u64,
        unique_exits: u64,
    }
);

noodle!(serialize, deserialize,
    #[derive(Debug)]
    pub enum NodeResult<'a> {
        Coverage(Cow<'a, [u64]>),
        NewInput(Cow<'a, [u8]>),
        // Corpus(Cow<'a, [Cow<'a, [u8]>]>),
        UniqueExit(Cow<'a, str>, Cow<'a, [u8]>),
        Statistics(Statistics),
    }
);