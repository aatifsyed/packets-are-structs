use macaddr::MacAddr6;
use std::{
    fmt::{self, Debug},
    mem::{size_of, ManuallyDrop},
    net::Ipv4Addr,
    ptr::{addr_of, addr_of_mut, read_unaligned, write_unaligned},
};

pub trait Ratify {
    fn ratify(&mut self) {}
}
impl<const N: usize> Ratify for [u8; N] {}
impl Ratify for [u8] {}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct EthertypeOrLength(pub u16);

#[derive(Debug, Clone, Copy)]
#[repr(packed)]
pub struct EtherTag {
    pub tpid: u16,
    pub tci: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(packed)]
pub struct EthernetHeader<const NUM_TAGS: usize> {
    pub destination: MacAddr6,
    pub source: MacAddr6,
    pub vlan: [EtherTag; NUM_TAGS],
    pub ethertype_or_length: EthertypeOrLength,
}

#[derive(Copy)]
#[repr(packed)]
pub struct Ethernet<Payload: ?Sized, const NUM_TAGS: usize> {
    pub eth_hdr: EthernetHeader<NUM_TAGS>,
    pub eth_body: ManuallyDrop<Payload>,
}
impl<Payload: Sized + Debug + Copy, const NUM_TAGS: usize> Debug for Ethernet<Payload, NUM_TAGS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let eth_hdr = unsafe { read_unaligned(addr_of!(self.eth_hdr)) };
        let eth_body = unsafe { read_unaligned(addr_of!(self.eth_body)) };
        let eth_body = ManuallyDrop::into_inner(eth_body);
        f.debug_struct("Ethernet")
            .field("eth_hdr", &eth_hdr)
            .field("eth_body", &eth_body)
            .finish()
    }
}

impl<Payload: Sized + Copy, const NUM_TAGS: usize> Clone for Ethernet<Payload, NUM_TAGS> {
    fn clone(&self) -> Self {
        let eth_hdr = unsafe { read_unaligned(addr_of!(self.eth_hdr)) };
        let eth_body = unsafe { read_unaligned(addr_of!(self.eth_body)) };
        Self { eth_hdr, eth_body }
    }
}

impl<Payload: Sized + Ratify + Copy, const NUM_TAGS: usize> Ratify for Ethernet<Payload, NUM_TAGS> {
    fn ratify(&mut self) {
        let mut body = self.eth_body();
        body.ratify();
        self.set_eth_body(body);
    }
}

impl<Payload: Sized, const NUM_TAGS: usize> Ethernet<Payload, NUM_TAGS> {
    pub fn new(eth_hdr: EthernetHeader<NUM_TAGS>, eth_body: Payload) -> Self {
        Self {
            eth_hdr,
            eth_body: ManuallyDrop::new(eth_body),
        }
    }
}

impl<Payload: Sized + Copy, const NUM_TAGS: usize> Ethernet<Payload, NUM_TAGS> {
    pub fn eth_body(&self) -> Payload {
        let b = unsafe { read_unaligned(addr_of!(self.eth_body)) };
        ManuallyDrop::into_inner(b)
    }
    pub fn set_eth_body(&mut self, eth_body: Payload) {
        let eth_body = ManuallyDrop::new(eth_body);
        unsafe { write_unaligned(addr_of_mut!(self.eth_body), eth_body) }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Ipv4Option(u32);

#[derive(Debug, Clone, Copy)]
#[repr(packed)]
pub struct Ipv4Header<const NUM_OPTIONS: usize> {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub options: [Ipv4Option; NUM_OPTIONS],
}

#[derive(Copy)]
#[repr(packed)]
pub struct Ipv4<Payload: ?Sized, const NUM_OPTIONS: usize> {
    pub ipv4_hdr: Ipv4Header<NUM_OPTIONS>,
    pub ipv4_body: ManuallyDrop<Payload>,
}

impl<Payload: ?Sized + Debug + Copy, const NUM_OPTIONS: usize> Debug
    for Ipv4<Payload, NUM_OPTIONS>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ipv4_hdr = unsafe { read_unaligned(addr_of!(self.ipv4_hdr)) };
        let ipv4_body = unsafe { read_unaligned(addr_of!(self.ipv4_body)) };
        let ipv4_body = ManuallyDrop::into_inner(ipv4_body);
        f.debug_struct("Ipv4")
            .field("ipv4_hdr", &ipv4_hdr)
            .field("ipv4_body", &ipv4_body)
            .finish()
    }
}

impl<Payload: ?Sized + Copy, const NUM_OPTIONS: usize> Clone for Ipv4<Payload, NUM_OPTIONS> {
    fn clone(&self) -> Self {
        let ipv4_hdr = unsafe { read_unaligned(addr_of!(self.ipv4_hdr)) };
        let ipv4_body = unsafe { read_unaligned(addr_of!(self.ipv4_body)) };
        Self {
            ipv4_hdr,
            ipv4_body,
        }
    }
}

impl<Payload: Sized + Ratify + Copy, const NUM_OPTIONS: usize> Ratify
    for Ipv4<Payload, NUM_OPTIONS>
{
    fn ratify(&mut self) {
        let len: u16 = size_of::<Self>().try_into().unwrap();
        self.ipv4_hdr.total_length = len.to_be();
        self.ipv4_hdr.header_checksum = 0;

        let mut body = self.ipv4_body();
        body.ratify();
        self.set_ipv4_body(body);

        let words: &[u16] = unsafe {
            std::slice::from_raw_parts(
                addr_of!(self.ipv4_hdr) as _,
                size_of::<Ipv4Header<NUM_OPTIONS>>() / 2,
            )
        };

        self.ipv4_hdr.header_checksum = !wrapping_sum(words);
    }
}

impl<Payload: Sized, const NUM_OPTIONS: usize> Ipv4<Payload, NUM_OPTIONS> {
    pub fn new(ipv4_hdr: Ipv4Header<NUM_OPTIONS>, ipv4_body: Payload) -> Self {
        Self {
            ipv4_hdr: ipv4_hdr,
            ipv4_body: ManuallyDrop::new(ipv4_body),
        }
    }
}

impl<Payload: Sized + Copy, const NUM_OPTIONS: usize> Ipv4<Payload, NUM_OPTIONS> {
    pub fn ipv4_body(&self) -> Payload {
        let b = unsafe { read_unaligned(addr_of!(self.ipv4_body)) };
        ManuallyDrop::into_inner(b)
    }
    pub fn set_ipv4_body(&mut self, ipv4_body: Payload) {
        let eth_body = ManuallyDrop::new(ipv4_body);
        unsafe { write_unaligned(addr_of_mut!(self.ipv4_body), eth_body) }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(packed)]
pub struct UDPHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Copy)]
#[repr(packed)]
pub struct UDP<Payload: ?Sized> {
    pub udp_hdr: UDPHeader,
    pub udp_body: ManuallyDrop<Payload>,
}

impl<Payload: ?Sized + Debug + Copy> Debug for UDP<Payload> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let udp_hdr = unsafe { read_unaligned(addr_of!(self.udp_hdr)) };
        let udp_body = unsafe { read_unaligned(addr_of!(self.udp_body)) };
        let udp_body = ManuallyDrop::into_inner(udp_body);
        f.debug_struct("UDP")
            .field("udp_hdr", &udp_hdr)
            .field("udp_body", &udp_body)
            .finish()
    }
}
impl<Payload: ?Sized + Copy> Clone for UDP<Payload> {
    fn clone(&self) -> Self {
        let udp_hdr = unsafe { read_unaligned(addr_of!(self.udp_hdr)) };
        let udp_body = unsafe { read_unaligned(addr_of!(self.udp_body)) };
        Self { udp_hdr, udp_body }
    }
}

impl<Payload: Sized + Copy + Ratify> Ratify for UDP<Payload> {
    fn ratify(&mut self) {
        let mut body = self.udp_body();
        body.ratify();
        self.set_udp_body(body);

        self.udp_hdr.checksum = 0;
        let len: u16 = size_of::<Payload>().try_into().unwrap();

        self.udp_hdr.length = len.to_be();
    }
}

impl<Payload: Sized> UDP<Payload> {
    pub fn new(udp_hdr: UDPHeader, udp_body: Payload) -> Self {
        Self {
            udp_hdr,
            udp_body: ManuallyDrop::new(udp_body),
        }
    }
}

impl<Payload: Sized + Copy> UDP<Payload> {
    pub fn udp_body(&self) -> Payload {
        let b = unsafe { read_unaligned(addr_of!(self.udp_body)) };
        ManuallyDrop::into_inner(b)
    }
    pub fn set_udp_body(&mut self, udp_body: Payload) {
        let udp_body = ManuallyDrop::new(udp_body);
        unsafe { write_unaligned(addr_of_mut!(self.udp_body), udp_body) }
    }
}

fn wrapping_sum(b: &[u16]) -> u16 {
    let sum = b.into_iter().fold(0u32, |acc, el| acc + *el as u32);
    let intermediate = unsafe { std::mem::transmute::<_, [u16; 2]>(sum) };
    if cfg!(target_endian = "big") {
        let [carry, sum] = intermediate;
        sum + carry
    } else {
        let [sum, carry] = intermediate;
        sum + carry
    }
}

#[cfg(test)]
mod tests {
    use as_bytes::AsBytes as _;
    use pcap_file::PcapWriter;
    use std::fs::File;

    use super::*;
    #[test]
    fn create_pcap() -> anyhow::Result<()> {
        let mut packet = Ethernet::new(
            EthernetHeader {
                destination: MacAddr6::broadcast(),
                source: MacAddr6::new(0, 1, 2, 3, 4, 5),
                vlan: [],
                ethertype_or_length: EthertypeOrLength(0x0008),
            },
            Ipv4::new(
                Ipv4Header {
                    version_ihl: 0b0100_0101,
                    dscp_ecn: 0,
                    total_length: 0,
                    identification: 0,
                    flags_fragment_offset: 0,
                    ttl: 100,
                    protocol: 0x11,
                    header_checksum: 0,
                    source: Ipv4Addr::LOCALHOST,
                    destination: Ipv4Addr::BROADCAST,
                    options: [],
                },
                UDP::new(
                    UDPHeader {
                        source_port: 5060,
                        destination_port: 0,
                        length: 0,
                        checksum: 0,
                    },
                    *b"hello, my name is Aatif",
                ),
            ),
        );
        packet.ratify();

        let bytes = unsafe { packet.as_bytes() };
        PcapWriter::new(File::create("test.pcap")?)?.write(0, 0, bytes, bytes.len().try_into()?)?;

        Ok(())
    }
}
