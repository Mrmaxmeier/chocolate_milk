//! A kernel written all in Rust

#![feature(panic_info_message, alloc_error_handler, llvm_asm, global_asm)]
#![feature(const_in_array_repeat_expressions)]

#![no_std]
#![no_main]

extern crate core_reqs;

#[allow(unused_imports)]
#[macro_use] extern crate alloc;

#[allow(unused_imports)]
#[macro_use] extern crate noodle;

#[macro_use] pub mod core_locals;
#[macro_use] pub mod print;
pub mod panic;
pub mod mm;
pub mod interrupts;
pub mod apic;
pub mod acpi;
pub mod intrinsics;
pub mod pci;
pub mod net;
pub mod time;
pub mod vtx;
pub mod snapshotted_app;

use alloc::vec::Vec;

use lockcell::LockCell;
use page_table::PhysAddr;
use core_locals::LockInterrupts;
use snapshotted_app::SnapshottedApp;

/// Release the early boot stack such that other cores can use it by marking
/// it as available
fn release_early_stack() {
    unsafe { mm::write_phys(PhysAddr(0x7e00), 1u8); }
}

/// Entry point of the kernel!
#[no_mangle]
pub extern fn entry(boot_args: PhysAddr, core_id: u32) -> ! {
    // Release the early boot stack, now that we have our own stack
    release_early_stack();

    // Initialize the core locals, this must happen first.
    core_locals::init(boot_args, core_id);
     
    // Calibrate the TSC so we can use `time` routines
    if core_id == 0 { unsafe { time::calibrate(); } }
    
    // Initialize interrupts
    interrupts::init();

    // Initialize the APIC
    unsafe { apic::init(); }
    
    if core!().id == 0 {
        // One-time initialization for the whole kernel

        // Initialize PCI devices
        unsafe { pci::init() }

        // Bring up all APICs on the system and also initialize NUMA
        // information with the memory manager through the use of the ACPI
        // information.
        unsafe { acpi::init() }
    }

    fn enable_avx() {
        let cpu_features = cpu::get_cpu_features();
        assert!(cpu_features.avx, "AVX not supported");
        unsafe {
        llvm_asm!(r#"
            xor ecx, ecx
            xgetbv
            or eax, 7
            xsetbv
            "# ::: "rcx", "rax", "memory" : "volatile", "intel");
        }
    }
    enable_avx();

    // Enable the APIC timer
    unsafe { core!().apic().lock().as_mut().unwrap().enable_timer(); }

    // Now we're ready for interrupts!
    unsafe { core!().enable_interrupts(); }

    // Let ACPI know that we've booted, it'll be happy to know we're here!
    // This will also serialize until all cores have come up. Once all cores
    // are online this will release all of the cores. This ensures that no
    // kernel task ends up hogging locks which are needed during bootloader
    // stack creation on other cores. This makes sure that by the time cores
    // get free reign of execution, we've intialized all cores to a state where
    // NMIs and soft reboots work.
    acpi::core_checkin();
    if core!().id != 0 { cpu::halt(); }

    {
        use core::sync::atomic::Ordering;
        use alloc::sync::Arc;
        use page_table::VirtAddr;

        static SNAPSHOT:
            LockCell<Option<Arc<SnapshottedApp>>, LockInterrupts> =
            LockCell::new(None);

        // Create the master snapshot, and fork from it for all cores

        let server = "192.168.122.1:1911";
        let name = "falkdump";

        let snapshot = {
            let mut snap = SNAPSHOT.lock();
            if snap.is_none() {
                *snap = Some(Arc::new(SnapshottedApp::new(server, name)));
            }
            snap.as_ref().unwrap().clone()
        };


        let fuzz_meta = crate::net::netmapping::NetMapping::new(
            server, &format!("{}.fuzz", name), true)
                .expect("Failed to netmap memory file for snapshotted app");


        // Create a new worker for the snapshot
        let mut worker = snapshot.worker();

        // Save the current time and compute a time in the future to print
        // status messages
        let it = cpu::rdtsc();
        let mut next_print = time::future(1_000_000);

        let buffer_addr;
        let buffer_size;
        {
            use core::convert::TryInto;
            buffer_addr = u64::from_le_bytes(fuzz_meta[..8].try_into().unwrap());
            buffer_size = usize::from_le_bytes(fuzz_meta[8..16].try_into().unwrap());
        }

        print!("buffer_addr: {:#x}\n", buffer_addr);
        print!("buffer_size: {:#x}\n", buffer_size);
        let BUFFER_ADDR: VirtAddr = VirtAddr(buffer_addr);
        let BUFFER_SIZE: usize    = buffer_size;

        let mut corpus = Vec::new(); // TODO: share corpus between cores
        let mut input = vec![0; BUFFER_SIZE];
        worker.read(BUFFER_ADDR, &mut input).unwrap();
        corpus.push(input.clone());

        let mut full_coverage_run = true;

        loop {
            if core!().id == 0 && cpu::rdtsc() >= next_print {
                let fuzz_cases = snapshot.fuzz_cases.load(Ordering::SeqCst);
                let coverage   = snapshot.coverage.lock().len();

                print!("{:12} cases | {:12.3} fcps | {:6} coverage\n",
                       fuzz_cases, fuzz_cases as f64 / time::elapsed(it),
                       coverage);
                next_print = time::future(1_000_000);
            }

            worker.reset();

            if (worker.rng.rand() % 128) == 0 {
                input.copy_from_slice(&corpus[worker.rng.rand() % corpus.len()]);
            }

            // Corrupt the input
            {
                for _ in 0..worker.rng.rand() % 4 {
                    let offset = worker.rng.rand() % BUFFER_SIZE;
                    input[offset as usize] = worker.rng.rand() as u8;
                }
            }
            worker.write(BUFFER_ADDR, &input).unwrap();

            if worker.run_fuzz_case(full_coverage_run) {
                if !full_coverage_run {
                    corpus.push(input.clone());
                    print!("new seed! corpus size: {}\n", corpus.len());
                    print!("> {:?}\n", alloc::string::String::from_utf8_lossy(&input));
                    full_coverage_run = true;
                } else {
                    full_coverage_run = false;
                }
            } else {
                full_coverage_run = false;
            }

            if let Some(netdev) = crate::net::NetDevice::get() {
                let _ = netdev.recv();
            }
        }
    }
}

