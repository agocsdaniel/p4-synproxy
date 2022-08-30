/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define TIMER_COUNT 15
#define MSS_SERVER_ENCODING_VALUE 1
//represents MSS 1460

#define SERVER_ADDRESS 3232278578

#define SERVER_PORT 0
#define CLIENT_PORT 1

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#include "types.p4"
#include "headers.p4"

struct learn_connection_t {
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<8> protocol;
    bit<32> seqDiff;
    bit<32> seqDiff_rev;
}

struct learn_debug_t {
    bit<32> data;   // data fields are set depending on the debug parameters
    bit<32> extra_1;
    bit<32> extra_2;
    bit<32> extra_3;
}


struct metadata {
    bit<1> is_valid_cookie;
//    bit<32> connectionHash;
//    bit<32> connectionHash_rev;
    bit<1> is_connection_established;
    bit<32> tempDiff;
    bit<32> cookieValue;
    bit<16> tcpLength; // this value is computed for each packet for TCP checksum recalculations
    learn_connection_t seq_digest; // Structure for sending digest messages that contain connection information and seqNo
    learn_debug_t debug_digest; // Structure for sending debug digest messages with Type 0
    bit<1> debug_bool;
}

#include "parser.p4"
#include "egress.p4"
#include "checksum.p4"



/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control MyIngress(inout headers hdr, inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action compute_cookie_value(bit <32> cookieIp, bit <16> cookiePort) {
        //ref" https://cr.yp.to/syncookies.html
        //generate a valid cookie, check limitations on each part
        //syn cookie is the initial sequence number selected by the proxy
        // first 5 bits: t mod 32, where t is 32 bit time counter
        // next 3 bits: encoding of MSS selected by the server in response to client's MSS
        // bottom 24 bits: hash of client IP address port and t
        // random value for all connections for now
        bit<5> time = TIMER_COUNT;   //constant value for time
        bit<3> mss_encoding = MSS_SERVER_ENCODING_VALUE; //random value for mss encvoding
        bit<24> hash_value;

        //metadata has a timestamp standard_metadata.enq_timestamp ---> bit <32>

        // compute the hash over source address and port number in addition to time counter
        //check if you need information for the server as well inside the hash or just the client!
        hash(hash_value, HashAlgorithm.crc16, (bit<24>)0, {
            cookieIp,
            cookiePort,
            time
            }, (bit<24>)2^24);

        //TODO: find an alternative way to concatenate bit strings --> P4_16 spec says ++ but it does not work!
    	bit <8> temp = (bit<8>)time;
    	bit <8> tempWT = temp << 3;
    	bit <8> tempWTE = tempWT | (bit<8>)mss_encoding;
    	bit <32> tempSeq = (bit<32>)tempWTE;
    	bit <32> tempSeqS = tempSeq << 24;
        meta.cookieValue = tempSeqS | (bit<32>)hash_value;
    }

    action compute_cookie_value_with_direction() {
        bit <32> cookieIp = hdr.ipv4.srcAddr;
        bit <16> cookiePort = hdr.tcp.srcPort;
        
        //if(hdr.ipv4.srcAddr == SERVER_ADDRESS){
        if(standard_metadata.ingress_port == SERVER_PORT){
            cookieIp = hdr.ipv4.dstAddr;
            cookiePort = hdr.tcp.dstPort;
        }

        compute_cookie_value(cookieIp, cookiePort);
    }

    action send_digest_connection() {
        compute_cookie_value_with_direction();
        meta.seq_digest.srcAddr = hdr.ipv4.srcAddr;
        meta.seq_digest.dstAddr = hdr.ipv4.dstAddr;
        meta.seq_digest.srcPort = hdr.tcp.srcPort;
        meta.seq_digest.dstPort = hdr.tcp.dstPort;
        meta.seq_digest.protocol = hdr.ipv4.protocol;
        meta.seq_digest.seqDiff = meta.cookieValue - hdr.tcp.seqNo;
        meta.seq_digest.seqDiff_rev = hdr.tcp.seqNo - meta.cookieValue;

        //digest packet
        digest(1, meta.seq_digest);
    }

    action send_digest_debug(bit<32> extra) {
        //send digest message to control plane, structure can be adjusted to send any data for debugging
        meta.debug_digest.data = (bit<32>)meta.debug_bool;
        meta.debug_digest.extra_1 = extra;

        //digest packet
        digest(1, meta.debug_digest);
    }


    action drop() {
        mark_to_drop();
    }

    // forward packet to the appropriate port

    action send_on_the_same_phy() {
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action send_on_the_other_phy() {
        if (standard_metadata.ingress_port == SERVER_PORT) {
            standard_metadata.egress_spec = CLIENT_PORT;
        } else if (standard_metadata.ingress_port == CLIENT_PORT) {
            standard_metadata.egress_spec = SERVER_PORT;
        }
    }

    action reverse_mac_addresses() {
        bit<48> srcMAC = hdr.ethernet.srcAddr;
        bit<48> dstMAC = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = srcMAC;
        hdr.ethernet.srcAddr = dstMAC;
    }

    action reverse_ipv4_addresses() {
        bit<32> clientAddr = hdr.ipv4.srcAddr;
        bit<32> serverAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.srcAddr = serverAddr;
        hdr.ipv4.dstAddr = clientAddr;
    }

    action reverse_tcp_ports() {
        bit<16> clientPort = hdr.tcp.srcPort;
        bit<16> serverPort = hdr.tcp.dstPort;
        hdr.tcp.dstPort = clientPort;
        hdr.tcp.srcPort = serverPort;
    }

    action swap_addresses() {
        reverse_mac_addresses();
        reverse_ipv4_addresses();
        reverse_tcp_ports();
    }

    action return_to_sender() {
        send_on_the_same_phy();
        swap_addresses();
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        //standard_metadata.egress_spec = port;
        //hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        //hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // for TCP checksum calculations, TCP checksum requires some IPv4 header fields in addition to TCP checksum that is
    //not present as a value and must be computed, tcp length = length in bytes of TCP header + TCP payload
    // from IPv4 header we have ipv4 total length that is a sum of the ip header and the ip payload (in our case) the TCP length
    // IPv4 length is IHL field * 4 bytes (or 32 bits 8*4), therefore, tcp length = ipv4 total length - ipv4 header length
    action compute_tcp_length(){
        bit<16> tcpLength;
        bit<16> ipv4HeaderLength = ((bit<16>) hdr.ipv4.ihl) * 4;
        //this gives the size of IPv4 header in bytes, since ihl value represents
        //the number of 32-bit words including the options field
        tcpLength = hdr.ipv4.totalLen - ipv4HeaderLength;
        // save this value to metadata to be used later in checksum computation
        meta.tcpLength = tcpLength;
    }


    // create SYN-cookie packet or SYN-ACK in response to a new connection from a client that is not whitelisted
    action create_syn_cookie_packet(){
        //This action is using the SYN packet received from the client and transform it to SYN-ACK
        //SeqNo is replaced with custom cookie value computed based in several values.

        //Save all the values before exchangiung them, to be used for hash later
        bit <32> cookieIp = hdr.ipv4.srcAddr;
        bit <16> cookiePort = hdr.tcp.srcPort;

        // return to sender
        return_to_sender();

        // set data offset to 5, to indicate that no options are included
        // hdr.tcp.dataOffset=5;  // ignore dataoffset did not solve retransmission issues
        // parsing TCP option is also complicated and removed. use random MSS encoding value

        // set SYN-ACK flags to create the second packet in the TCP handshake
        hdr.tcp.syn = 1;
        hdr.tcp.ack = 1;

        // set the Acknowledgement number to the sequence number received + size of packet (check from wireshark)
        hdr.tcp.ackNo = hdr.tcp.seqNo + 1;

        compute_cookie_value(cookieIp, cookiePort);
        hdr.tcp.seqNo = meta.cookieValue;
    }

    //Validate SYN cookie received from a client, last packet in the handshake
    //if a valid cookie is received, the client information is added to whitelist (bloom filter)
    action validate_syn_cookie(){
        // check if the sequence number of SYN-ACK packet is a valid cookie for the client
        compute_cookie_value(hdr.ipv4.srcAddr, hdr.tcp.srcPort);

        // cookie sequence number is ack -1
        if(hdr.tcp.ackNo - 1 == meta.cookieValue){
            meta.is_valid_cookie = 1;
        }else{
            meta.is_valid_cookie = 0;
        }
    }

    action create_new_tcp_connection(){
        //this action is used to create a new tcp connection between the proxy and the server
        // minimal flags are set, this action is called based on the ACK packet received
        
        // Remove payload from received ACK, but does not work
        //truncate((bit<32>)54);
        //hdr.ipv4.totalLen = (bit<16>)40;
        //standard_metadata.packet_length = (bit<14>)54;

        // Alter TCP
        hdr.tcp.syn = 1;
        hdr.tcp.ack = 0;

        hdr.tcp.seqNo = hdr.tcp.seqNo - 1;
        hdr.tcp.ackNo = 0;

        hdr.tcp.dataOffset = 5;

        send_on_the_other_phy();
    }

    // create ACK response for the SYN-ACK packet received from the server.
    // This action is used to establish a spoofed TCP connection between proxy and server
    action create_ack_response(){
        // reverse src and dst
        return_to_sender();

        // set data offset to 5, to indicate that no options are included
        // hdr.tcp.dataOffset = 5; // not required, checksum was the cause of the re-transmission problem

        // set ACK flags to create the final packet in the TCP handshake
        hdr.tcp.syn = 0;
        hdr.tcp.ack = 1;
        hdr.tcp.psh = 0;

        // set sequence number to the acknowledgement number expected by server
        bit <32> serverSeq = hdr.tcp.seqNo;
        bit <32> serverAck = hdr.tcp.ackNo;
        hdr.tcp.seqNo = serverAck;

        // set the Acknowledgement number to the sequence number received + size of payload (check from wireshark)
        hdr.tcp.ackNo = serverSeq + 1;
    }

    action saveDifferenceValue(bit<32> difference){
        meta.tempDiff = difference;
    }

    action forward_request(){
        // sequence number should remain the same since we used the same sequence number for the second TCP connection
        // the connection table has seqNo of the previous connection stored which can be used to compute the correct ACK

        // this function will forward all traffic from both sides after translation if the connection is established
        // if the packet is sent by the client --> update the ACK number
        // if the packet is sent by the server --> update the sequence number
        // you should have the difference
        bit<32> sequence = hdr.tcp.seqNo;
        bit<32> acknowledgment = hdr.tcp.ackNo;

        //if(hdr.ipv4.srcAddr == SERVER_ADDRESS){
        if(standard_metadata.ingress_port == SERVER_PORT){
            //meta.debug_bool=1;
            hdr.tcp.seqNo = sequence + meta.tempDiff;
        } else {
            //meta.debug_bool=0;
            hdr.tcp.ackNo = acknowledgment + meta.tempDiff;
        }
        //send_digest_debug(meta.tempDiff);
        
        send_on_the_other_phy();
    }

    // we have one table responsible for forwarding packets
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;   // maximum number of entries in the table
        default_action = drop();
    }

    table connections {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.srcPort: exact;
            hdr.tcp.dstPort: exact;
            hdr.ipv4.protocol: exact;
        }
        actions = {
            saveDifferenceValue;
            NoAction;
        }
        size = 4096;
        default_action = NoAction;
    }


    apply {
        // Normal forwarding scenario after processing based on the scenario
        //if (hdr.ipv4.isValid()) {
        //    ipv4_lpm.apply();
        //}

        if(hdr.ipv4.isValid() && hdr.tcp.isValid()){
            if(connections.apply().hit){
                meta.is_connection_established = 1;
            }else{
                meta.is_connection_established = 0;
            }

            //check if the connection is established to forward, otherwise discard
            if (meta.is_connection_established == 1){
                //sequence and acknowledgment numbers should be adapted to the new connection
                forward_request();
            }else{
                if(hdr.tcp.syn == 1 && hdr.tcp.ack == 0 && hdr.tcp.psh == 0){
                       create_syn_cookie_packet();
                }else if(hdr.tcp.ack == 1 && hdr.tcp.syn == 0 && hdr.tcp.psh == 0){
                    // if the packet is a ACK response for the TCP handshake
                    // check cookie value first if it is a valid cookie or not
                    validate_syn_cookie();
                    if(meta.is_valid_cookie == 1){
                        //reset the meta value, but why?
                        meta.is_valid_cookie = 0;
                        // after receiving the final ACK from the client create a new TCP connection with the server.
                        //create a new TCP connection between Proxy-server, using same initial sequence number as client
                        create_new_tcp_connection();
                    }else{
                        // if it is not valid cookie, just drop the packet
                        drop();
                        return;
                    }
                }else if(hdr.tcp.ack == 1 && hdr.tcp.syn == 1 && hdr.tcp.psh == 0){
                    //if you receive SYN-ACK from server to create a TCP connection
                    // change the same packet and transform it into ACK packet.
                    // add both connection and reverse to connection list
                    send_digest_connection();
                    create_ack_response();
                }else{
                    drop();
                    return;
                }
            }
        } else {
            send_on_the_other_phy();
        }
        

        if (hdr.tcp.isValid()) {
            // TCP length is required for TCP header checksum value calculations.
            // compute TCP length after modification of TCP header
            //compute_tcp_length();
        }
    }
}



/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
DummyEgress(),
MyComputeChecksum(),
DummyDeparser()
) main;
