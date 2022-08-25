#include "headers.p4"

/*************************************************************************
*********************** P A R S E R  *************************************
*************************************************************************/

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            0x86DD: parse_ipv6;
            0x0806: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            0x01: parse_icmp;
            0x06: parse_tcp;
            0x11: parse_udp;
            default: accept;
        }
    }

    state parse_ipv6 {
        /*packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.protocol) {
            0x01: parse_icmp;
            0x06: parse_tcp;
            0x11: parse_icmp;
            default: accept;
        }*/
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
    
    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

}




/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DummyDeparser(packet_out packet, in headers hdr) {
    apply { }
}