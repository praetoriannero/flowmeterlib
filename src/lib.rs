use std::fmt;
use pcap;

pub fn list_devices() {
    for device in pcap::Device::list().expect("device lookup failed!") {
        println!("Found device name {:?} - {:?}", device.name, device.desc.unwrap());
    }
}

#[derive(Debug, Clone)]
pub struct HwAddress([u8; 6]);

#[derive(Debug, Clone)]
pub struct IPv4Address([u8; 4]);

#[derive(Debug, Clone)]
pub struct IPv6Address([u8; 6]);

#[derive(Debug, Clone)]
pub enum IPAddress {
    IPv4Address,
    IPv6Address
}

#[derive(Debug, Clone)]
pub struct Netflow {
    src_mac: HwAddress,
    dst_mac: HwAddress,
    src_ip: IPAddress,
    dst_ip: IPAddress,
    sport: u16,
    dport: u16,
    vlan_id: u8,
    transport_proto: u8,
}

impl fmt::Display for HwAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "{:X?}:{:X?}:{:X?}:{:X?}:{:X?}:{:X?}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5]
        )
    }
}

impl Netflow {
    pub fn to_string(&self) -> String {
        format!(
            "{:?}-{:?}-{:?}-{:?}-{:?}-{:?}-{:?}-{:?}",
            self.src_mac,
            self.dst_mac,
            self.src_ip,
            self.dst_ip,
            self.sport,
            self.dport,
            self.vlan_id,
            self.transport_proto
        )
    }

    pub fn array_test(self) {
        let new_mac: HwAddress = HwAddress([0, 0, 0, 0, 0, 0]);
        println!("{:?}", new_mac);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_devices() {
        list_devices();
    }
}
