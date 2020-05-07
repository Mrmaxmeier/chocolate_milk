use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::borrow::Cow;

use falktp::ServerMessage;
use noodle::Serialize;

use crate::net::{NetDevice, UdpAddress};
use crate::snapshotted_app::Rng;


pub struct Netlink {
    device: Arc<NetDevice>,
    server: UdpAddress,
    rng: Rng,
}

impl Netlink {
    pub fn new(server: &str) -> Self {
        // Get access to a network device
        let device = NetDevice::get().unwrap();

        // Bind to a random UDP port on this network device
        let udp = NetDevice::bind_udp(device.clone()).unwrap();

        // Resolve the target
        let server = UdpAddress::resolve(
            &device, udp.port(), server)
            .expect("Couldn't resolve target address");
                
                
        Netlink {
            device,
            server,
            rng: Rng::new(),
        }
    }

    pub fn poll(&self) {
        // handle ARPs
        let _ = self.device.recv();
    }

    pub fn publish(&self, msg: falktp::NodeResult) {
        let mut buf = Vec::new();
        msg.serialize(&mut buf);
        self.send_reliable(&buf);
    }

    fn send_reliable(&self, msg: &[u8]) {
        const MTU: usize = 1472 - 8*2;
        let mut offset = 0u64;

        let uuid = self.rng.rand() as u64;
        let length = msg.len();
        let checksum = falktp::Checksum::compute(&msg);

        for chunk in msg.chunks(MTU) {
            let mut packet = self.device.allocate_packet();
            {
                let mut pkt = packet.create_udp(&self.server);
                let chunk = Cow::Borrowed(chunk);
                ServerMessage::SlightlyLossyTransport {
                    uuid,
                    length,
                    checksum,
                    offset,
                    chunk
                }.serialize(&mut pkt).unwrap();
            }
            offset += chunk.len() as u64;
            self.device.send(packet, true);
        }
    }
}