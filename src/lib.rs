use std::fmt;
use pcap;
use pnet::packet::{ethernet::EthernetPacket, Packet};
use pnet::packet::ipv4::Ipv4Packet;

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
pub struct FlowID {
    src_mac: HwAddress,
    dst_mac: HwAddress,
    src_ip: IPAddress,
    dst_ip: IPAddress,
    sport: u16,
    dport: u16,
    vlan_id: u8,
    transport_proto: u8,
}

impl fmt::Display for IPv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "{:?}.{:?}.{:?}.{:?}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
        )
    }
}

impl fmt::Display for IPv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "{:?}:{:?}:{:?}:{:?}:{:?}:{:?}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5],
        )
    }
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

impl FlowID {
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

pub struct FlowStats {

}

pub struct Meter<T: pcap::State> {
    handle: pcap::Capture<T>,
    flow_cache: std::collections::HashMap<FlowID, FlowStats>,
}

impl<T: pcap::State> Meter<T> {
    pub fn consume(buf: &[u8]) {
        let eth_pdu: Option<EthernetPacket<'_>> = EthernetPacket::new(buf);
        if let Some(eth_pdu) = eth_pdu {
            // can we check the underlying ethernet type??
            // would save us some headache about trying out a bunch of different options
            let ip_pdu: Option<Ipv4Packet<'_>> = Ipv4Packet::new(eth_pdu.payload());
            // build ipv4 flow id
            if ip_pdu.is_some() {}
            
        }
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
