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
pub mod corpus;

use lockcell::LockCell;
use page_table::PhysAddr;
use core_locals::LockInterrupts;
use snapshotted_app::SnapshottedApp;
use corpus::{Corpus, CorpusHandle};

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

    {
        use core::sync::atomic::Ordering;
        use alloc::sync::Arc;

        static SNAPSHOT:
            LockCell<Option<Arc<SnapshottedApp>>, LockInterrupts> =
            LockCell::new(None);


        static CORPUS:
            LockCell<Option<Arc<Corpus>>, LockInterrupts> =
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

        let mut corpus = {
            let mut corpus = CORPUS.lock();
            if corpus.is_none() {
                *corpus = Some(Arc::new(Corpus::new()));
            }
            CorpusHandle::new(corpus.as_ref().unwrap().clone())
        };

        // Create a new worker for the snapshot
        let mut worker = snapshot.worker();

        // Save the current time and compute a time in the future to print
        // status messages
        let it = cpu::rdtsc();
        let mut next_print = time::future(1_000_000);

        let buffer_addr = snapshot.buffer_addr;
        let buffer_size = snapshot.buffer_size;

        print!("buffer_addr: {:#x}\n", buffer_addr.0);
        print!("buffer_size: {:#x}\n", buffer_size);

        // let mut corpus = Vec::new(); // TODO: share corpus between cores
        let mut input = vec![0; buffer_size];
        corpus.push(input.clone());
        worker.read(buffer_addr, &mut input).unwrap();
        corpus.push(input.clone());

        let mut full_coverage_run = true;

        for fuzzcase in 0u64.. {
            if fuzzcase & 0xfff == 0 {
                corpus.sync();
            }

            if core!().id == 0 && cpu::rdtsc() >= next_print {
                let fuzz_cases = snapshot.fuzz_cases.load(Ordering::SeqCst);
                let coverage   = snapshot.coverage.lock().len();

                print!("{:12} cases | {:12.3} fcps | {:6} coverage\n",
                       fuzz_cases, fuzz_cases as f64 / time::elapsed(it),
                       coverage);

                // SETUP: kvm 4 cores
                // sample 0x3ff
                //       183046 cases |   183044.315 fcps |   3976 coverage
                //    212816193 cases |   173735.439 fcps |   7077 coverage => 1224s

                // sample 0xfff + more mutations
                //     17295429 cases |   243382.899 fcps |   5981 coverage
                //    129412997 cases |   242218.140 fcps |   6532 coverage
                //    169076992 cases |   240706.914 fcps |   6703 coverage
                //    228227950 cases |   238591.356 fcps |   6775 coverage => 956s

                // sample 0x3ff + more mutations
                //      9357956 cases |   179870.110 fcps |   6235 coverage
                //     38210607 cases |   182733.999 fcps |   6970 coverage => 209s
                //    100179233 cases |   182046.749 fcps |   7062 coverage => 550s
                //    140375286 cases |   181025.352 fcps |   7078 coverage => 775s

                // sample 0xff + more mutations
                //      4772980 cases |    83683.670 fcps |   6117 coverage => 57s
                //     13830754 cases |    84805.055 fcps |   6855 coverage => 163s
                //     29630238 cases |    86082.349 fcps |   7124 coverage => 344s
                //     64442708 cases |    88590.469 fcps |   7287 coverage => 727s

                // sample 0x3f + more mutations
                //      6450806 cases |    37259.435 fcps |   6858 coverage => 173s
                //     10693760 cases |    37761.682 fcps |   7147 coverage => 283s
                //     37235641 cases |    37475.980 fcps |   7364 coverage => 993s
                //     54660318 cases |    36516.051 fcps |   7384 coverage


                // Send coverage updates
                {
                    use alloc::vec::Vec;
                    use crate::net::{NetDevice, UdpAddress};
                    use falktp::ServerMessage;
                    use crate::noodle::Serialize;
                    use alloc::borrow::Cow;


                    let coverage = {
                        snapshot.coverage.lock()
                            .iter()
                            .copied()
                            .collect::<Vec<_>>()
                    };


                    // Get access to a network device
                    let netdev = NetDevice::get().unwrap();

                    // Bind to a random UDP port on this network device
                    let udp = NetDevice::bind_udp(netdev.clone()).unwrap();

                    // Resolve the target
                    let server = UdpAddress::resolve(
                        &netdev, udp.port(), server)
                        .expect("Couldn't resolve target address");


                    let mut offset = 0u64;
                    for chunk in coverage.chunks(1472/8 - 4) {
                        let mut packet = netdev.allocate_packet();
                        {
                            let mut pkt = packet.create_udp(&server);
                            ServerMessage::CovUpdate {
                                total_length: coverage.len() as u64,
                                offset,
                                chunk: Cow::Borrowed(chunk),
                            }.serialize(&mut pkt).expect("failed to serialize CovUpdate");
                            offset += chunk.len() as u64;
                        }
                        netdev.send(packet, true);
                    }
                }

                next_print = time::future(1_000_000);

                // handle ARPs
                if let Some(netdev) = crate::net::NetDevice::get() {
                    let _ = netdev.recv();
                }
            }

            worker.reset();

            if !full_coverage_run {
                if (worker.rng.rand() % 128) == 0 {
                    input.copy_from_slice(
                        &corpus.entries[
                            worker.rng.rand() % corpus.entries.len()]);
                }

                // Corrupt the input

                for _ in 0..worker.rng.rand() % 4 {
                    match worker.rng.rand() % 4 {
                        0|1 => {
                            // replace
                            let offset = worker.rng.rand() % buffer_size;
                            input[offset as usize] = worker.rng.rand() as u8;
                        }
                        2 => {
                            // insert
                            if buffer_size < 2 { continue }
                            let offset = worker.rng.rand() % (buffer_size-1);
                            input.copy_within(offset..buffer_size-1, offset+1);
                            input[offset as usize] = worker.rng.rand() as u8;
                        }
                        3 => {
                            // duplicate / reduce entropy
                            let offset_a = worker.rng.rand() % buffer_size;
                            let offset_b = worker.rng.rand() % buffer_size;
                            input[offset_a as usize] = input[offset_b as usize];
                        }
                        _ => unreachable!(),
                    }
                };
            }
            worker.write(buffer_addr, &input).unwrap();

            let mut pushed_new_seed = false;
            if worker.run_fuzz_case(full_coverage_run) {
                if !full_coverage_run {
                    corpus.push(input.clone());
                    corpus.sync();
                    pushed_new_seed = true;
                }
            }
            full_coverage_run = pushed_new_seed;
        }
        panic!("That's a lot of fuzz cases!")
    }
}

