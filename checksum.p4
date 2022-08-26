#include "headers.p4"

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control DummyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(
	        hdr.ipv4.isValid(), {
              hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control DummyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
	        hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
	            hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );

        update_checksum_with_payload(
	        hdr.tcp.isValid(), // && hdr.ipv4.isValid(),
            {
                hdr.ipv4.srcAddr,
	            hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                16w0, //tcp length should be here, but that way it makes invalid checksum
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.res,
                hdr.tcp.cwr,
                hdr.tcp.ece,
                hdr.tcp.urg,
                hdr.tcp.ack,
                hdr.tcp.psh,
                hdr.tcp.rst,
                hdr.tcp.syn,
                hdr.tcp.fin,
                hdr.tcp.window,
                hdr.tcp.urgentPtr
            },
            hdr.tcp.checksum,
            HashAlgorithm.csum16
        );
/*
        update_checksum_with_payload(
	        hdr.icmp.isValid(), // && hdr.ipv4.isValid(),
            {
                hdr.ipv4.srcAddr,
	            hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                0x04,
                hdr.icmp.icmp_type,
                hdr.icmp.icmp_code,
                16w0
            },
            hdr.icmp.icmp_csum,
            HashAlgorithm.csum16
        );*/
    }
}