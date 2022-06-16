/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>

//Ethernet types
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP = 0x0806;

//IPv4 protocols
const bit<8> PROT_ICMP = 1;
const bit<8> PROT_TCP = 6;
const bit<8> PROT_UDP = 17;

//Temporal limiting variables
const bit<48> deltaTime = 1000; 		//Length of the timeframe (us), default 1000 (1ms)
const bit<48> packetLimit = 10;			//limit of packets in one timeframe, default 10
register<bit<48>>(1) regPacketCount; 	//number of packets in current timeframe
register<bit<48>>(1) regPrevTime; 		//time at the start of the current timeframe (us)

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
error { //define a new error type
    WrongPacketType
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
                
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 	  : parse_ipv4; //check if type is IPv4
            default      : reject_packet; //reject packets by default
        }
    }
    state reject_packet{ //reject packet
    	verify(false, error.WrongPacketType); //set an error flag to use in ingress
    	transition accept;	
    }
    
    state parse_ipv4{ //extract header
    	packet.extract(hdr.ipv4);
    	log_msg("Package accepted");
    	transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    bit<1> validFlag; //Flag showing if current packet is allowed to pass
    bit<1> timeFlag; //Flag raised when packet limit is reached
    
    action packet_drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        //Change addresses
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr; //Update source address
        hdr.ethernet.dstAddr = dstAddr; //Update destination address
        
        //Decrement ttl
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        
        //Forward using appropriate port
        standard_metadata.egress_spec = port; //Send packet
    }
    
    table ipv4_lpm { //Table with lpm address matching
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            packet_drop;
            NoAction;
        }
        size = 1024;
        default_action = packet_drop();
    }
    
    action ipv4_valid(){ //Set the valid flag to true
    	validFlag = 1;
    	log_msg("Valid protocol (IPv4 {})", {hdr.ipv4.protocol});
    }
    
    table ipv4_protocol { //Static table for protocol checking
        key = {
            hdr.ipv4.protocol: exact;
        }
        actions = {
            ipv4_valid;
            NoAction;
        }
        
        const default_action = NoAction;
        const entries = { //ipv4_valid() for whitelisted protocols
        PROT_ICMP:	ipv4_valid();
        PROT_TCP:	ipv4_valid();
        PROT_UDP:	NoAction();
        	
        }
    }

    apply {
    	//Check if not over packet limit
    	bit<48> prevTime;
    	bit<48> curTime = standard_metadata.ingress_global_timestamp;
    	bit<48> packetCount;
    	timeFlag = 0;
    	regPrevTime.read(prevTime, 0);
		
    	if(curTime - prevTime > deltaTime || curTime < prevTime){
    		regPrevTime.write(0, curTime);
    		regPacketCount.write(0, 0);
    		//Reset the registers if timeframe is over or time underflow
    	}
    	else{
    		regPacketCount.read(packetCount, 0);
    		if(packetCount > packetLimit){
    			timeFlag = 1;
    		}
    		else{
    			packetCount++;
    			regPacketCount.write(0, packetCount);
    		}
    	}
    	
    		
    	if(timeFlag == 1){
    		packet_drop();
    	}
    	else{
    		if (standard_metadata.parser_error != error.NoError) {
    			packet_drop(); //Drop packets if any error detected
    			exit;
			}
        	else if (hdr.ipv4.isValid()) { //Do ipv4 processing if valid  
            		validFlag = 0; //Ensure flag is set to 0
            		ipv4_protocol.apply(); //Check the protocol
            		if (validFlag == 1){
            			ipv4_lpm.apply(); //Forward if valid
            		}
            		else {
            			packet_drop(); //Drop otherwise
            		}
        	} 
        	else {
            		packet_drop();
        	}
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
