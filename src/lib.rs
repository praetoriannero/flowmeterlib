use pcap;

pub fn list_devices() {
    for device in pcap::Device::list().expect("device lookup failed!") {
        println!("Found device name {:?} - {:?}", device.name, device.desc.unwrap());
    }
}

pub type HwAddress = [u8; 6];
pub type IPv4Address = [u8; 4];
pub type IPv6Address = [u8; 6];

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_devices() {
        list_devices();
    }
}
