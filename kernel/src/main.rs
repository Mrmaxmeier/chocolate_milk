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
pub mod progress_set;
pub mod mutate;
pub mod netlink;

use lockcell::LockCell;
use page_table::PhysAddr;
use core_locals::LockInterrupts;
use snapshotted_app::SnapshottedApp;
use netlink::Netlink;
use mutate::Mutator;

use alloc::borrow::Cow;

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
    // unsafe { core!().apic().lock().as_mut().unwrap().enable_timer(); }

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

    // if core!().id != 0 { cpu::halt(); }

    {
        use core::sync::atomic::Ordering;
        use alloc::sync::Arc;

        static SNAPSHOT:
            LockCell<Option<Arc<SnapshottedApp>>, LockInterrupts> =
            LockCell::new(None);

        static NETLINK:
            LockCell<Option<Arc<Netlink>>, LockInterrupts> =
            LockCell::new(None);

        // Create the master snapshot, and fork from it for all cores

        let server = "192.168.122.1:1911";
        let name = "tex";

        let snapshot = {
            let mut snap = SNAPSHOT.lock();
            if snap.is_none() {
                let snapshot = SnapshottedApp::new(server, name);
                *snap = Some(Arc::new(snapshot));
            }
            snap.as_ref().unwrap().clone()
        };

        let netlink = {
            let mut nl = NETLINK.lock();
            if nl.is_none() {
                *nl = Some(Arc::new(Netlink::new(server)));
            }
            nl.as_ref().unwrap().clone()
        };

        // Create a new worker for the snapshot
        let mut worker = snapshot.worker();

        // Populate coverage set with initial coverage
        worker.reset();
        worker.run_trace(true);

        // Save the current time and compute a time in the future to print
        // status messages
        let it = cpu::rdtsc();
        let mut next_print = time::future(1_000_000);
        let mut next_net_poll = time::future(250_000);
        let mut next_net_push = time::future(250_000);
        let mut next_explore = time::future(10_000_000);
        let mut last_net_push_coverage = 0;

        let buffer_addr = snapshot.buffer_addr;
        let buffer_size = snapshot.buffer_size;

        let mut input = vec![0; buffer_size];
        worker.corpus.insert(&input);
        worker.read(buffer_addr, &mut input).unwrap();
        worker.corpus.insert(&input);


        let dictionary = [
            /*
            &b" cnf 0 0"[..],
            &b" c prior 0 0"[..],
            */
        ];

        let mut results = false;
        for fuzzcase in 0u64.. {
            // Periodically sync corpus with other cores.
            if fuzzcase & 0xfff == 0 || results {
                worker.sync();

                let time = cpu::rdtsc();
                if core!().id == 0 && time >= next_print {
                    let fuzz_cases = snapshot.fuzz_cases.load(Ordering::SeqCst);
                    let vm_exits   = snapshot.vm_exits.load(Ordering::SeqCst);
                    let millis_tracing = snapshot.millis_tracing.load(Ordering::SeqCst);
                    let coverage   = snapshot.coverage.lock().len();

                    print!("{:6.1}s | {:12} cases | {:12.3} fcps \
                            | {:6} cov | {:4} corp | {:2} ux \
                            | {:6.1} vme/fc | {:6.1}s ss'd\n",
                        time::elapsed(it), fuzz_cases,
                        fuzz_cases as f64 / time::elapsed(it), coverage,
                        worker.corpus.len(), worker.exits.len(),
                        vm_exits as f64 / fuzz_cases as f64,
                        millis_tracing as f64 / 1000.,
                    );

                    if time::elapsed(it) <= 10. {
                        next_print = time::future(1_000_000);
                    } else if time::elapsed(it) <= 25. {
                        next_print = time::future(2_500_000);
                    } else {
                        next_print = time::future(10_000_000);
                    }
                }

                if time >= next_explore && false {
                    use alloc::vec::Vec;
                    let coverage = {
                        snapshot.coverage.lock()
                            .iter()
                            .copied()
                            .collect::<Vec<_>>()
                    };
                    if !coverage.is_empty() && worker.rng.rand() % 2 == 0 {
                        let idx = worker.rng.rand() % coverage.len();
                        worker.hardware_breakpoint = Some(coverage[idx]);
                        worker.explore_coverage.clear();
                        worker.explore_corpus.clear();
                    } else {
                        worker.hardware_breakpoint = None;
                    }
                    next_explore = time::future(1_000_000);
                }

                if core!().id == 0 && time >= next_net_poll {
                    netlink.poll();
                    next_net_poll = time::future(250_000);
                }


                // Send coverage updates
                if core!().id == 0 && time >= next_net_push {
                    let coverage = snapshot.coverage.lock().len();
                    if coverage > last_net_push_coverage {
                        last_net_push_coverage = coverage;
                        use alloc::vec::Vec;
                        use crate::net::{NetDevice, UdpAddress};
                        use falktp::ServerMessage;
                        use crate::noodle::Serialize;

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
                    next_net_push = time::future(250_000);
                }
            }

            worker.reset();

            let mutator = Mutator {
                rng: &worker.rng,
                corpus: &worker.corpus,
                explore_corpus: &worker.explore_corpus,
                dictionary: &dictionary,
                buffer_size,
            };
            mutator.mutate(&mut input);

            worker.write(buffer_addr, &input).unwrap();
            let exit_reason = worker.run_fuzz_case();

            if worker.exits.insert(&exit_reason) {
                worker.fuzz_case_new_coverage += 1;
                print!("\nUnique exit reason! {:x?}\n", exit_reason);
                print!("> {:?}\n\n",
                    alloc::string::String::from_utf8_lossy(&input));

                let reason_str = format!("{:x?}", exit_reason);
                let msg = falktp::NodeResult::UniqueExit(
                    Cow::Borrowed(&reason_str),
                    Cow::Borrowed(&input),
                );
                netlink.publish(msg);
            }

            if worker.hardware_breakpoint.is_some() {
                if worker.explore_coverage.insert(worker.fuzz_case_explore) {
                    worker.explore_corpus.push(input.clone());
                }
            }

            results = worker.fuzz_case_new_coverage > 0;
            if worker.fuzz_case_new_coverage > 0 {
                results = true;
                // make sure that the whole trace is recorded in our coverage set
                worker.reset();
                worker.write(buffer_addr, &input).unwrap();
                worker.run_trace(true);

                /*
                let trace_hash = worker.run_trace(true);
                // cheap tricks to try to reduce input entropy
                // TODO: this is painfully slow! use a lossy similarity metric instead?
                for i in 0..input.len() {
                    let orig = input[i];
                    if orig == 0 { continue; }

                    if input[i] != b'A' && !(i != 0 && input[i] == input[i-1]) {
                        input[i] = b'A';
                        worker.reset();
                        worker.write(buffer_addr, &input).unwrap();
                        if worker.run_trace(false) == trace_hash {
                            continue;
                        }
                    }

                    if i != 0 && input[i] != input[i-1] {
                        input[i] = input[i-1];
                        worker.reset();
                        worker.write(buffer_addr, &input).unwrap();
                        if worker.run_trace(false) == trace_hash {
                            continue;
                        }
                    }
                    input[i] = orig;
                }
                */

                if worker.corpus.insert(&input) {
                    let mut update_string_buf = alloc::string::String::new();
                    update_string_buf.extend([' '; 100].iter());
                    update_string_buf += &format!("\r{:+5} > {:?} \r",
                        worker.fuzz_case_new_coverage,
                        alloc::string::String::from_utf8_lossy(&input)
                    );

                    if let Some((idx, _)) = update_string_buf
                            .char_indices().nth(101+94) {
                        update_string_buf.truncate(idx);
                        update_string_buf += " [...]\r"
                    }

                    print!("{}", update_string_buf);

                    netlink.publish(
                        falktp::NodeResult::NewInput(Cow::Borrowed(&input)));
                }
            }

            // Update number of fuzz cases
            worker.snapshot.fuzz_cases.fetch_add(1, Ordering::SeqCst);
        }

        panic!("Enough fuzzing for now :^)")
    }
}

