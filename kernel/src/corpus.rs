use core::sync::atomic::{AtomicU64, Ordering};
use alloc::vec::Vec;
use alloc::sync::Arc;
use lockcell::LockCell;

pub struct Corpus {
    entries: Arc<LockCell<Vec<Vec<u8>>, crate::LockInterrupts>>,
    epoch: AtomicU64,
}

impl Corpus {
    pub fn new() -> Self {
        let entries = Arc::new(LockCell::new(Vec::new()));
        let epoch = AtomicU64::new(0);
        Corpus { entries, epoch }
    }


    pub fn push(&self, entry: Vec<u8>) {
        let mut entries = self.entries.lock();
        if entries.contains(&entry) { return; }
        print!("new seed! corpus size: {}\n", entries.len()+1);
        print!("> {:?}\n", alloc::string::String::from_utf8_lossy(&entry));
        entries.push(entry);
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }
}

pub struct CorpusHandle {
    pub entries: Vec<Vec<u8>>,
    epoch: u64,
    corpus: Arc<Corpus>,
}

impl CorpusHandle {
    pub fn new(corpus: Arc<Corpus>) -> Self {
        CorpusHandle {
            entries: Vec::new(),
            epoch: 0,
            corpus
        }
    }

    pub fn push(&mut self, entry: Vec<u8>) {
        self.entries.push(entry.clone());
        self.corpus.push(entry);
    }

    pub fn sync(&mut self) {
        let remote = self.corpus.epoch.load(Ordering::SeqCst);
        if remote != self.epoch {
            self.entries.clear();
            let entries = self.corpus.entries.lock();
            self.entries.extend_from_slice(&entries);
            self.epoch = remote;
        }
    }
}