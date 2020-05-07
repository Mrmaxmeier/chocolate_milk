// TODO: input min/max/exact size

use crate::progress_set::ProgressSetHandle;
use alloc::vec::Vec;
use crate::snapshotted_app::Rng;

pub struct Mutator<'a> {
    pub rng: &'a Rng,
    pub corpus: &'a ProgressSetHandle<Vec<u8>>,
    pub explore_corpus: &'a [Vec<u8>],
    pub dictionary: &'a [&'a [u8]],
    pub buffer_size: usize,
}

impl<'a> Mutator<'a> {
    fn odds(&self, n: usize) -> bool {
        self.rng.rand() % n == 0
    }

    pub fn mutate(&self, input: &mut [u8]) {
        if self.odds(128) {
            self.replace(input);
        }

        for _ in 0..(self.rng.rand() % 4 + 1) {
            self.corrupt(input);
        }
    }

    fn replace(&self, input: &mut [u8]) {
        if self.explore_corpus.len() > 1 && (self.rng.rand() % 2) == 0 {
            let samples = &self.explore_corpus;
            input.copy_from_slice(
                &samples[self.rng.rand() % samples.len()]);
        } else {
            input.copy_from_slice(
                self.corpus.sample(self.rng.rand()));
        }
    }

    // used for splicing
    fn word(&self) -> Option<&[u8]> {
        if !self.corpus.entries.is_empty() &&
                (self.rng.rand() % 2 == 0 ||
                self.dictionary.is_empty()) {
            let entry = self.corpus.sample(self.rng.rand());
            if entry.len() < 5 { return None; }
            let offset = self.rng.rand() % (entry.len()-4);
            let size = self.rng.rand() % (entry.len() - offset - 2);
            return Some(&entry[offset..offset+size+2]);
        } else if !self.dictionary.is_empty() {
            return Some(self.dictionary[self.rng.rand() % self.dictionary.len()]);
        }
        None
    }

    fn corrupt(&self, input: &mut [u8]) {
        match self.rng.rand() % 6 {
            0|1 => {
                // flip
                let offset = self.rng.rand() % self.buffer_size;
                let bit = self.rng.rand() % 8;
                input[offset as usize] ^= 1u8 << bit;
            }
            2 => {
                // replace
                let offset = self.rng.rand() % self.buffer_size;
                input[offset as usize] = self.rng.rand() as u8;
            }
            3 => {
                // insert
                if self.buffer_size < 2 { return; }
                if self.odds(16) {
                    // insert from dict / splice
                    if let Some(word) = self.word() {
                        let offset = self.rng.rand() % (self.buffer_size-word.len());
                        input.copy_within(
                            offset..self.buffer_size-word.len(), offset+word.len());
                        input[offset..offset+word.len()].copy_from_slice(word);
                    }
                } else {
                    // insert random char
                    let offset = self.rng.rand() % (self.buffer_size-1);
                    input.copy_within(offset..self.buffer_size-1, offset+1);
                    input[offset as usize] = self.rng.rand() as u8;
                };
            }
            4 => {
                // delete
                if self.buffer_size < 2 { return; }
                let offset = self.rng.rand() % (self.buffer_size-1);
                input.copy_within(offset+1..self.buffer_size, offset);
                input[self.buffer_size-1] = self.rng.rand() as u8;
            }
            5 => {
                // duplicate / reduce entropy
                let offset_a = self.rng.rand() % self.buffer_size;
                let offset_b = self.rng.rand() % self.buffer_size;
                input[offset_a as usize] = input[offset_b as usize];
            }
            _ => unreachable!(),
        }
    }
}
