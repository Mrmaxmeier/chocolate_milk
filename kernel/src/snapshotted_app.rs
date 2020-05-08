//! Fuzzable snapshotted application backed by an Intel VT-x VM

use core::cell::Cell;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};
use core::alloc::Layout;
use core::convert::TryInto;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::collections::{BTreeSet, BTreeMap};
use hashbrown::HashSet;

use crate::mm;
use crate::vtx::{Vm, FxSave, RegisterState, VmExit};
use crate::vtx::Exception::{self, *};
use crate::net::netmapping::NetMapping;
use crate::core_locals::LockInterrupts;
use crate::progress_set::{ProgressSet, ProgressSetHandle};

use lockcell::LockCell;
use page_table::{PhysAddr, VirtAddr, PhysMem, PageType, Mapping};
use page_table::{PAGE_PRESENT, PAGE_WRITE, PAGE_USER, PAGE_NX};

/// Parsed snapshot information file
struct SnapshotInfo {
    /// Register state for the snapshot
    regs: RegisterState,

    /// Memory region info
    virt_to_offset: BTreeMap<VirtAddr, usize>,

    /// Memory region info
    virt_to_flags: BTreeMap<VirtAddr, (bool, bool, bool)>,
}

/// A shared state for a snapshot of an application which is being fuzzed
pub struct SnapshottedApp<'a> {
    /// Parse information about the snapshot. This is the `.info` file produced
    /// by the Sausage Factory. This contains information such as the register
    /// states of the target application as well as what virtual addresses
    /// map to offsets in the backing memory
    snapshot_info: Arc<SnapshotInfo>,

    /// Raw memory contents which back the original snapshot. This is a packed
    /// format and thus the `snapshot_info` can be used to take the sparse
    /// virtual addresses and convert them into the `memory` offsets.
    memory: Arc<NetMapping<'a>>,

    /// Coverage database containing all observed RIP values
    // TODO: transition to ProgressSet?
    pub coverage: LockCell<BTreeSet<u64>, LockInterrupts>,

    pub exits: Arc<ProgressSet<ExitReason>>,

    pub corpus: Arc<ProgressSet<Vec<u8>>>,

    /// Number of fuzz cases performed on the target
    pub fuzz_cases: AtomicU64,
    pub vm_exits: AtomicU64,
    pub millis_tracing: AtomicU64,

    pub buffer_addr: VirtAddr,
    pub buffer_size: usize,
}

impl<'a> SnapshottedApp<'a> {
    /// Creates a new snapshotted application based on the snapshot `name`.
    ///
    /// This snapshot currently must be in the Sausage Factory file format.
    /// The name should be the base name of the files, such that `name.info`
    /// and `name.memory` are valid filenames on the file server
    pub fn new(server: &str, name: &str) -> Self {
        // Network map the memory file contents as read-only
        let memory = NetMapping::new(server, &format!("{}.memory", name), true)
            .expect("Failed to netmap memory file for snapshotted app");

        // Network map the info file contents as read-only
        let info = NetMapping::new(server, &format!("{}.info", name), true)
            .expect("Failed to netmap info file for snapshotted app");

        let fuzz_meta = NetMapping::new(server, &format!("{}.fuzz", name), true)
            .expect("Failed to netmap info file for snapshotted app");
        
        info.populate();
        fuzz_meta.populate();
        memory.populate();

        // Create a new register state
        let mut regs = RegisterState::default();

        // Get access to the snapshot info
        let mut ptr = &info[..];

        /// Consume a `$ty` from the snapshot info and update the pointer
        macro_rules! consume {
            ($ty:ty) => {{
                let val: $ty = <$ty>::from_le_bytes(
                    ptr[..size_of::<$ty>()].try_into().unwrap());
                ptr = &ptr[size_of::<$ty>()..];
                val
            }}
        }

        // Parse out the register fields from the snapshot info
        regs.rfl = consume!(u64);
        regs.r15 = consume!(u64);
        regs.r14 = consume!(u64);
        regs.r13 = consume!(u64);
        regs.r12 = consume!(u64);
        regs.r11 = consume!(u64);
        regs.r10 = consume!(u64);
        regs.r9  = consume!(u64);
        regs.r8  = consume!(u64);
        regs.rdi = consume!(u64);
        regs.rsi = consume!(u64);
        regs.rbp = consume!(u64);
        regs.rdx = consume!(u64);
        regs.rcx = consume!(u64);
        regs.rbx = consume!(u64);
        regs.rax = consume!(u64);
        regs.rsp = consume!(u64);

        regs.rip = consume!(u64);
        regs.gs_base = consume!(u64);
        regs.fs_base = consume!(u64);

        // Parse the `FxSave` out of the info
        unsafe {
            regs.fxsave = core::ptr::read_unaligned(
                ptr[..512].as_ptr() as *const FxSave);
            ptr = &ptr[512..];
        }

        // Construct the virtual to memory offset table
        let mut virt_to_offset = BTreeMap::new();
        let mut virt_to_flags = BTreeMap::new();

        // File contains a dynamic amount of MEMORY_BASIC_INFORMATION
        // structures until the end of the file
        assert!(ptr.len() % 0x20 == 0, "Invalid shape for info file");
        for chunk in ptr.chunks(0x20) {
            // Parse out the section base and size
            let base = u64::from_le_bytes(
                chunk[0x00..0x08].try_into().unwrap());
            let size = u64::from_le_bytes(
                chunk[0x08..0x10].try_into().unwrap());
            let offset = usize::from_le_bytes(
                chunk[0x10..0x18].try_into().unwrap());
            let flags = u64::from_le_bytes(
                chunk[0x18..0x20].try_into().unwrap());
            
            let flag_r = flags & 1 != 0;
            let flag_w = flags & 2 != 0;
            let flag_x = flags & 4 != 0;

            // Make sure the size is non-zero and the base and the size are
            // both 4 KiB aligned
            assert!(size > 0 && base & 0xfff == 0 && size & 0xfff == 0);

            let mut section_offset = 0;
            // Create the virtual to offset mappings
            for page in (base..=(base.checked_add(size - 1).unwrap()))
                    .step_by(4096) {
                // Create a mapping from each page in the virtual address
                // space of the dumped process, into the offset into the
                // memory backing for the snapshot.
                assert!((offset + section_offset) % 0x1000 == 0,
                    "netmapped page not 4k aligned");
                virt_to_offset.insert(VirtAddr(page), offset + section_offset);
                virt_to_flags.insert(VirtAddr(page), (flag_r, flag_w, flag_x));
                section_offset += 4096;
            }
        }

        let buffer_addr = VirtAddr(u64::from_le_bytes(fuzz_meta[..8].try_into().unwrap()));
        let buffer_size = usize::from_le_bytes(fuzz_meta[8..16].try_into().unwrap());

        // Return out the snapshotted application
        SnapshottedApp {
            snapshot_info: Arc::new(SnapshotInfo {
                regs,
                virt_to_offset,
                virt_to_flags,
            }),
            memory:         Arc::new(memory),
            coverage:       LockCell::new(BTreeSet::new()),
            exits:          Arc::new(ProgressSet::new()),
            corpus:         Arc::new(ProgressSet::new()),
            fuzz_cases:     AtomicU64::new(0),
            vm_exits:       AtomicU64::new(0),
            millis_tracing: AtomicU64::new(0),
            buffer_addr,
            buffer_size,
        }
    }

    /// Create a new worker for this snapshot
    pub fn worker(&self) -> Worker {
        // Create a new virtual machine
        let vm = Vm::new_user();

        Worker {
            vm,
            snapshot: self,
            exits:    self.exits.handle(),
            corpus:   self.corpus.handle(),
            rng:      Rng::new(),
            explore_coverage: HashSet::new(),
            explore_corpus: Vec::new(),
            hardware_breakpoint: None,
            fuzz_case_new_coverage: 0,
            fuzz_case_explore: 0,
        }
    }
}

/// A random number generator based off of xorshift64
pub struct Rng(Cell<u64>);

impl Rng {
    /// Create a new randomly seeded `Rng`
    pub fn new() -> Self {
        let rng = Rng(Cell::new(((core!().id as u64) << 48) | cpu::rdtsc()));
        for _ in 0..1000 { rng.rand(); }
        rng
    }

    /// Get the next random number from the random number generator
    pub fn rand(&self) -> usize {
        let orig_seed = self.0.get();

        let mut seed = orig_seed;
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 43;
        self.0.set(seed);

        orig_seed as usize
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum ExitReason {
    InvalidOpcode { rip: u64, bytes: [u8; 8] },
    UnhandledSyscall { rip: u64, rax: u64 },
    UnhandledPageFault { rip: u64, addr: u64, write: bool },
    UnhandledException { rip: u64, exception: crate::vtx::Exception },
    Timeout,
}

/// A worker for fuzzing a `SnapshottedApp`
pub struct Worker<'a> {
    /// Snapshotted application that we're a worker for fuzzing
    pub snapshot: &'a SnapshottedApp<'a>,

    /// Virtual machine for running the application
    pub vm: Vm,

    pub exits: ProgressSetHandle<ExitReason>,

    pub corpus: ProgressSetHandle<Vec<u8>>,

    pub explore_coverage: HashSet<u64>,
    pub explore_corpus: Vec<Vec<u8>>,

    pub hardware_breakpoint: Option<u64>,

    /// Random number generator seed
    pub rng: Rng,

    pub fuzz_case_new_coverage: u64,
    pub fuzz_case_explore: u64,
}

impl<'a> Worker<'a> {
    pub fn reset(&mut self) {
        // Load the original snapshot registers
        self.vm.guest_regs = self.snapshot.snapshot_info.regs;
       
        // Reset memory to its original state
        unsafe {
            let memory         = &self.snapshot.memory;
            let virt_to_offset = &self.snapshot.snapshot_info.virt_to_offset;
            self.vm.page_table.for_each_dirty_page(
                    &mut mm::PhysicalMemory, |addr, page| {
                let offset = virt_to_offset[&addr];

                // Get mutable access to the underlying page
                let psl = mm::slice_phys_mut(page, 4096);

                // Copy the original page into the modified copy of the page
                llvm_asm!(r#"
                  
                    mov rcx, 4096 / 8
                    rep movsq

                "# ::
                "{rdi}"(psl.as_ptr()),
                "{rsi}"(memory.get_unchecked(offset..).as_ptr()) :
                "memory", "rcx", "rdi", "rsi", "cc" : 
                "intel", "volatile");
            });
        }
    }



    // TODO: impl Iterator<u64>?
    pub fn run_trace(&mut self, update_coverage: bool) -> Vec<u64> {
        let it = cpu::rdtsc();
        let mut trace = Vec::with_capacity(
            self.snapshot.coverage.lock().len()
        );

        // Enable single stepping
        self.vm.guest_regs.rfl |= 1 << 8;
        self.vm.preemption_timer = None;
        self.vm.hardware_breakpoint = None;

        'vm_loop: loop {
            if trace.len() > 1_000_000 {
                print!("[WARN] timeout during run_trace\n");
                return trace;
            }
            // Run the VM until a VM exit
            let vmexit = self.vm.run();
            self.snapshot.vm_exits.fetch_add(1, Ordering::Relaxed);

            match vmexit {
                VmExit::Exception(PageFault { addr, write, .. }) => {
                    if self.translate(addr, write).is_none() {
                        break 'vm_loop;
                    }
                }
                VmExit::Exception(InvalidOpcode) => {
                    if self.handle_invalid_opcode().is_err() {
                        break 'vm_loop;
                    }
                }
                VmExit::Exception(DebugException) => {
                    trace.push(self.vm.guest_regs.rip);
                    if update_coverage && self.snapshot.coverage.lock()
                            .insert(self.vm.guest_regs.rip) {
                        self.fuzz_case_new_coverage += 1;
                    }
                }
                VmExit::ExternalInterrupt => {
                    // Host interrupt happened, ignore it
                }
                VmExit::Exception(Exception::NMI) => {
                    // NMIs mean we need to NMI ourself as we might need to
                    // TLB shootdown or halt ourselves. The system may be going
                    // down for a soft reboot
                    unsafe {
                        let mut apic = core!().apic().lock();
                        let apic = apic.as_mut().unwrap();
                        apic.ipi(core!().apic_id().unwrap(),
                            (1 << 14) | (4 << 8));
                    }

                    // Handled the NMI, re-enter the VM
                    continue;
                }
                VmExit::Exception(_) => {
                    break 'vm_loop;
                }
                x @ _ => panic!("Unhandled VM exit {:?}", x),
            }
        }

        let elapsed = crate::time::elapsed(it);
        self.snapshot.millis_tracing.fetch_add(
            (elapsed * 1000.) as u64, Ordering::SeqCst);

        trace
    }

    fn handle_invalid_opcode(&mut self) -> Result<(), ExitReason> {
        let mut buf = [0; 8];
        self.read(VirtAddr(self.vm.guest_regs.rip), &mut buf).unwrap();
        if !buf.starts_with(&[0x0f, 0x05]) {
            {
                // DEBUG
                let mut buf2 = [0; 8];
                self.read(VirtAddr(self.vm.guest_regs.rip), &mut buf2).unwrap();
                assert_eq!(buf, buf2);
                let page_start = self.vm.guest_regs.rip & (!0xfff);
                self.read(VirtAddr(page_start), &mut buf2).unwrap();
                print!("start of strange page ({:#x}):\n{:x?}\n", page_start, buf2);
                panic!();
            }
            return Err(ExitReason::InvalidOpcode {
                rip: self.vm.guest_regs.rip,
                bytes: buf,
            });
        }

        let syscall = self.vm.guest_regs.rax;
        match syscall {
            1 => { // linux sys_write
                let count = self.vm.guest_regs.rdx;
                self.vm.guest_regs.rax  = count;
                self.vm.guest_regs.rip += 2;
                return Ok(())
            }
            3 => { // linux sys_close
                self.vm.guest_regs.rax  = 0;
                self.vm.guest_regs.rip += 2;
                return Ok(())
            }
            9 => { // linux sys_mmap
                // glibc will use preallocated main arena if mmap fails
                self.vm.guest_regs.rax = !0; // MMAP_FAILED
                self.vm.guest_regs.rip += 2;
                return Ok(())
            }
            _ => {
                return Err(ExitReason::UnhandledSyscall {
                    rax: self.vm.guest_regs.rax,
                    rip: self.vm.guest_regs.rip,
                });
            },
        }
    }

    /// Execute a single fuzz case until completion
    pub fn run_fuzz_case(&mut self) -> ExitReason {
        self.fuzz_case_new_coverage = 0;
        self.fuzz_case_explore = 0;

        /*
        TODO: fix inconsistency
        UnhandledPageFault { rip: 7ffc0c572aa2, addr: 7ffc0c56e080 }
        */

        // Counter of number of single steps we should perform
        let mut single_step = 0;

        let mut timeout_instructions_remaining = 0x420_0000_u32;

        'vm_loop: loop {
            // Check if single stepping is requested
            if single_step > 0 {
                // Enable single stepping
                self.vm.guest_regs.rfl |= 1 << 8;

                // Decrement number of single steps requested
                if single_step > 0 {
                    single_step -= 1;
                }
            } else {
                // Disable single stepping
                self.vm.guest_regs.rfl &= !(1 << 8);
            }

            // Set the pre-emption timer for randomly breaking into the VM
            // to record coverage information
            let preemption_timer = (self.rng.rand() & 0x3ff) as u32 + 1;
            self.vm.preemption_timer = Some(preemption_timer);
            timeout_instructions_remaining =
                match timeout_instructions_remaining
                    .checked_sub(preemption_timer) {
                        Some(v) => v,
                        None => return ExitReason::Timeout
                    };

            // Prevent breakpoint loops by disabling breakpoints on single-step.
            // After we hit the hardware breakpoint, we'll enable single_step for
            // a few instrunctions.
            self.vm.hardware_breakpoint = if single_step == 0 {
                self.hardware_breakpoint
            } else {
                None
            };

            // Run the VM until a VM exit
            let vmexit = self.vm.run();
            self.snapshot.vm_exits.fetch_add(1, Ordering::Relaxed);


            match vmexit {
                VmExit::Exception(PageFault { addr, write, .. }) => {
                    if self.translate(addr, write).is_some() {
                        continue 'vm_loop;
                    }

                    return ExitReason::UnhandledPageFault {
                        rip: self.vm.guest_regs.rip,
                        addr: addr.0,
                        write,
                    };
                }
                VmExit::Exception(InvalidOpcode) => {
                    if let Err(exit) = self.handle_invalid_opcode() {
                        return exit;
                    }
                    continue 'vm_loop;
                }
                VmExit::Exception(DebugException) |
                VmExit::PreemptionTimer => {
                    if Some(self.vm.guest_regs.rip) == self.vm.hardware_breakpoint {
                        self.fuzz_case_explore =
                            self.fuzz_case_explore & 0xffffffffffff0000
                            | (self.fuzz_case_explore + 1) & 0xffff;
                        single_step = 4;
                    }
                    if self.snapshot.coverage.lock()
                            .insert(self.vm.guest_regs.rip) {
                        self.fuzz_case_new_coverage += 1;
                        single_step = 1000;
                    }
                    continue 'vm_loop;
                }
                VmExit::ExternalInterrupt => {
                    // Host interrupt happened, ignore it
                    continue 'vm_loop;
                }
                VmExit::Exception(Exception::NMI) => {
                    // NMIs mean we need to NMI ourself as we might need to
                    // TLB shootdown or halt ourselves. The system may be going
                    // down for a soft reboot
                    unsafe {
                        let mut apic = core!().apic().lock();
                        let apic = apic.as_mut().unwrap();
                        apic.ipi(core!().apic_id().unwrap(),
                            (1 << 14) | (4 << 8));
                    }

                    // Handled the NMI, re-enter the VM
                    continue;
                }
                VmExit::Exception(e) => {
                    return ExitReason::UnhandledException {
                        rip: self.vm.guest_regs.rip,
                        exception: e,
                    };
                }
                // x @ _ => panic!("Unhandled VM exit {:?}", x),
            }
        }
    }

    /// Read the contents of the virtual memory at `vaddr` in the guest into
    /// the `buf` provided
    ///
    /// Returns `None` if the request cannot be fully satisfied. It is possible
    /// that some reading did occur, but is partial.
    pub fn read(&mut self, mut vaddr: VirtAddr, mut buf: &mut [u8])
            -> Option<()> {
        // Nothing to do in the 0 byte case
        if buf.len() == 0 { return Some(()); }
        
        // Starting physical address (invalid paddr, but page aligned)
        let mut paddr = PhysAddr(!0xfff);

        while buf.len() > 0 {
            if (paddr.0 & 0xfff) == 0 {
                // Crossed into a new page, translate
                paddr = self.translate(vaddr, false)?;
            }

            // Compute the remaining number of bytes on the page
            let page_remain = 0x1000 - (paddr.0 & 0xfff);

            // Compute the number of bytes to copy
            let to_copy = core::cmp::min(page_remain as usize, buf.len());

            // Get mutable access to the underlying page and copy the memory
            // from the buffer into it
            let psl = unsafe { mm::slice_phys_mut(paddr, to_copy as u64) };
            buf[..to_copy].copy_from_slice(psl);

            // Advance the buffer pointers
            paddr = PhysAddr(paddr.0 + to_copy as u64);
            vaddr = VirtAddr(vaddr.0 + to_copy as u64);
            buf   = &mut buf[to_copy..];
        }

        Some(())
    }

    /// Write the contents of `buf` into the virtual memory at `vaddr` for
    /// the guest
    ///
    /// Returns `None` if the request cannot be fully satisfied. It is possible
    /// that some writing did occur, but is partial.
    pub fn write(&mut self, mut vaddr: VirtAddr, mut buf: &[u8]) -> Option<()>{
        // Nothing to do in the 0 byte case
        if buf.len() == 0 { return Some(()); }
        
        // Starting physical address (invalid paddr, but page aligned)
        let mut paddr = PhysAddr(!0xfff);

        while buf.len() > 0 {
            if (paddr.0 & 0xfff) == 0 {
                // Crossed into a new page, translate
                paddr = self.translate(vaddr, true)?;
            }

            // Compute the remaining number of bytes on the page
            let page_remain = 0x1000 - (paddr.0 & 0xfff);

            // Compute the number of bytes to copy
            let to_copy = core::cmp::min(page_remain as usize, buf.len());

            // Get mutable access to the underlying page and copy the memory
            // from the buffer into it
            let psl = unsafe { mm::slice_phys_mut(paddr, to_copy as u64) };
            psl.copy_from_slice(&buf[..to_copy]);

            // Advance the buffer pointers
            paddr = PhysAddr(paddr.0 + to_copy as u64);
            vaddr = VirtAddr(vaddr.0 + to_copy as u64);
            buf   = &buf[to_copy..];
        }

        Some(())
    }

    /// Translate a virtual address for the guest into a physical address on
    /// the host. If `write` is set, the translation will occur for a write
    /// access, and thus the copy-on-write will be performed on the page if
    /// needed to satisfy the write.
    ///
    /// If the virtual address is not valid for the guest, this will return
    /// `None`.
    ///
    /// The translation will only be valid for the page the `vaddr` resides in.
    /// The returned physical address will have the offset from the virtual
    /// address applied. Such that a request for virtual address `0x13371337`
    /// would return a physical address ending in `0x337`
    fn translate(&mut self, vaddr: VirtAddr, write: bool) -> Option<PhysAddr> {
        // Get access to the snapshot memory and information
        let memory         = &self.snapshot.memory;
        let virt_to_offset = &self.snapshot.snapshot_info.virt_to_offset;
        let virt_to_flags  = &self.snapshot.snapshot_info.virt_to_flags;

        // Page-align the address
        let align_addr = VirtAddr(vaddr.0 & !0xfff);

        // Get the offset into the memory buffer where this virtual address is
        // present. If the virtual address is not valid this will return `None`
        let offset = *virt_to_offset.get(&align_addr)?;

        let (flag_r, flag_w, flag_x) = *virt_to_flags.get(&align_addr)?;
        assert!(flag_r, "TODO: handle non-readable pages?");

        // Get access to physical memory
        let mut pmem = mm::PhysicalMemory;

        // Attempt to translate the page, it is possible it has not yet been
        // mapped and we need to page it in from the network mapped storage in
        // the `SnapshottedApp`
        let translation = self.vm.page_table.translate(&mut pmem, align_addr,
                                                       write);


        if vaddr.0 == 0x556dce882000 || vaddr.0 == 0x556dce8b1000 {
            print!("DEBUG translation of {:#x?}:\n{:#x?}\n", vaddr.0,
                translation);
        }

        let page = if let Some(Mapping {
                pte: Some(pte), page: Some(orig_page), .. }) = translation {
            // Page is mapped, it is possible it needs to be promoted to
            // writable
            
            // Check if we're requesting a write and the page is not currently
            // marked writeable
            if write && flag_w &&
                    (unsafe { mm::read_phys::<u64>(pte) } & PAGE_WRITE) == 0 {
                // Allocate a new page
                let page = pmem.alloc_phys(
                    Layout::from_size_align(4096, 4096).unwrap());

                // Get mutable access to the underlying page
                let psl = unsafe { mm::slice_phys_mut(page, 4096) };

                // Copy in the bytes to initialize the page from the network
                // mapped memory
                psl.copy_from_slice(&memory[offset..offset + 4096]);


                let mut flags = PAGE_PRESENT | PAGE_USER | PAGE_WRITE;
                if !flag_x { flags |= PAGE_NX; }

                assert!(vaddr.0 != 0x556dce882000 && vaddr.0 != 0x556dce8b1000);
                // Promote the page via CoW
                unsafe {
                    mm::write_phys(pte, page.0 | flags);
                }

                page
            } else {
                // Return the original mapped page
                orig_page.0
            }
        } else {
            // Page was not mapped
            if write && flag_w {
                // Page needs to be CoW-ed from the network mapped file

                // Allocate a new page
                let page = pmem.alloc_phys(
                    Layout::from_size_align(4096, 4096).unwrap());

                // Get mutable access to the underlying page
                let psl = unsafe { mm::slice_phys_mut(page, 4096) };

                // Copy in the bytes to initialize the page from the network
                // mapped memory
                psl.copy_from_slice(&memory[offset..offset + 4096]);

                let mut flags = PAGE_PRESENT | PAGE_USER;
                if flag_w { flags |= PAGE_WRITE; }
                if !flag_x { flags |= PAGE_NX; }

                unsafe {
                    // Map in the page as RW
                    self.vm.page_table.map_raw(&mut pmem, align_addr,
                        PageType::Page4K, page.0 | flags)
                        .unwrap();
                }

                // Return the physical address of the new page
                page
            } else {
                // Page is only being accessed for read. Alias the guest's
                // virtual memory directly into the network mapped page as
                // read-only

                // Touch the mapping to make sure it is downloaded and mapped
                unsafe { core::ptr::read_volatile(&memory[offset]); }

                // Look up the physical page backing for the mapping
                let page = {
                    // Get access to the host page table
                    let mut page_table = core!().boot_args.page_table.lock();
                    let page_table = page_table.as_mut().unwrap();

                    // Translate the mapping virtual address into a physical
                    // address
                    //
                    // This will always succeed as we touched the memory above
                    page_table.translate(&mut pmem,
                        VirtAddr(memory[offset..].as_ptr() as u64), false)
                        .map(|x| x.page).flatten()
                        .expect("Whoa, memory page not mapped?!").0
                };

                let mut flags = PAGE_PRESENT | PAGE_USER;
                if !flag_x { flags |= PAGE_NX; }

                unsafe {
                    // Map in the page as read-only into the guest page table
                    self.vm.page_table.map_raw(&mut pmem, align_addr,
                        PageType::Page4K, page.0 | flags).unwrap();
                }

                // Return the physical address of the backing page
                page
            }
        };

        // Return the physical address of the requested virtual address
        Some(PhysAddr(page.0 + (vaddr.0 & 0xfff)))
    }

    pub fn sync(&mut self) {
        self.exits.sync();
        self.corpus.sync();
    }
}

