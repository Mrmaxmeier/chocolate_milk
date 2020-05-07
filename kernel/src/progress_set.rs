use core::sync::atomic::{AtomicU64, Ordering};
use alloc::vec::Vec;
use alloc::sync::Arc;
use lockcell::LockCell;
use hashbrown::HashSet;
use core::hash::Hash;
use core::fmt::Debug;

pub struct ProgressSet<T: Hash + PartialEq + Eq + Debug + Clone> {
    pub entries: Arc<LockCell<HashSet<T>, crate::LockInterrupts>>,
    pub epoch: AtomicU64,
}

impl<T: Hash + PartialEq + Eq + Debug + Clone> ProgressSet<T> {
    pub fn new() -> Self {
        let entries = Arc::new(LockCell::new(HashSet::new()));
        let epoch = AtomicU64::new(0);
        ProgressSet { entries, epoch }
    }


    pub fn insert(&self, entry: T) -> bool {
        let mut entries = self.entries.lock();
        if entries.contains(&entry) { return false; }
        entries.insert(entry);
        self.epoch.fetch_add(1, Ordering::SeqCst);
        return true;
    }

    pub fn handle(self: &Arc<Self>) -> ProgressSetHandle<T> {
        ProgressSetHandle::new(Arc::clone(self))
    }
}

pub struct ProgressSetHandle<T: Hash + PartialEq + Eq + Debug + Clone> {
    pub entries: HashSet<T>,
    pub sample: Vec<T>,
    epoch: u64,
    remote: Arc<ProgressSet<T>>,
}

impl<T: Hash + PartialEq + Eq + Debug + Clone + Clone> ProgressSetHandle<T> {
    pub fn new(remote: Arc<ProgressSet<T>>) -> Self {
        ProgressSetHandle {
            entries: HashSet::new(),
            sample: Vec::new(),
            epoch: 0,
            remote
        }
    }

    pub fn insert(&mut self, entry: &T) -> bool {
        if self.entries.insert(entry.clone()) {
            self.sample.push(entry.clone());
            self.remote.insert(entry.clone())
        } else {
            false
        }
    }

    pub fn sample(&self, rnd: usize) -> &T {
        // TODO: bias towards new samples?
        assert!(!self.sample.is_empty(), "tried to sample empty ProgressSet");
        let idx = rnd % self.sample.len();
        &self.sample[idx]
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn sync(&mut self) {
        let remote = self.remote.epoch.load(Ordering::SeqCst);
        if remote != self.epoch {
            let entries = self.remote.entries.lock();
            for elem in entries.iter() {
                if self.entries.insert(elem.clone()) {
                    self.sample.push(elem.clone());
                }
            }
            self.epoch = remote;
        }
    }
}