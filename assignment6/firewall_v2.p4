/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>

//Ethernet types
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_IPV6 = 0x86dd;
const bit<16> TYPE_ARP = 0x0806;

//IPv4 protocols
const bit<8> PROT_ICMP = 1;
const bit<8> PROT_ICMPv6 = 58;
const bit<8> PROT_TCP = 6;
const bit<8> PROT_UDP = 17;

//Temporal limiting variables
const bit<48> deltaTime = 10000; 		//Length of the timeframe (us), default 1000 (10ms)
const bit<48> packetLimit = 10;			//limit of packets in one timeframe, default 10
register<bit<48>>(1) regPacketCount; 	//number of packets in current timeframe
register<bit<48>>(1) regPrevTime; 		//time at the start of the current timeframe (us)

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;

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

header ipv6_t {
    bit<4>  version;
    bit<8>  tc;
    bit<20> flowTable;
    bit<16> payloadLen;
    bit<8>  nextHeader;
    bit<8>  ttl;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv6_t		 ipv6;
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
            TYPE_IPV4 	 : parse_ipv4; //check if type is IPv4
            TYPE_IPV6 	 : parse_ipv6; //check if type is IPv6
            default      : reject_packet; //reject packets by default
        }
    }
    state reject_packet{ //reject packet
    	verify(false, error.WrongPacketType); //set an error flag to use in ingress
    	transition accept;	
    }
    
    state parse_ipv4{ //extract header v4
    	packet.extract(hdr.ipv4);
    	log_msg("Package accepted (v4)"); //Debug msg
    	transition accept;
    }
    
    state parse_ipv6{ //extract header v6
    	packet.extract(hdr.ipv6);
    	log_msg("Package accepted (v6)"); //Debug msg
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
    bit<1> blackListFlag; //Flag raised when source is on a blacklist
    
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
    
    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        //Change addresses
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr; //Update source address
        hdr.ethernet.dstAddr = dstAddr; //Update destination address
        
        //Decrement ttl
        hdr.ipv6.ttl = hdr.ipv6.ttl - 1;
        
        //Forward using appropriate port
        standard_metadata.egress_spec = port; //Send packet
    }
    
    table ipv4_lpm { //Table with v4 lpm address matching
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
    
    table ipv6_lpm { //Table with v6 lpm address matching
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            ipv6_forward;
            packet_drop;
            NoAction;
        }
        size = 1024;
        default_action = packet_drop();
    }
    
    action ipv4_block(){ //Set the blacklist flag v4
    	blackListFlag = 1;
    	log_msg("Blacklisted IPv4 {})", {hdr.ipv4.srcAddr}); //Debug msg
    }
    
    action ipv6_block(){ //Set the blacklist flag v6
    	blackListFlag = 1;
    	log_msg("Blacklisted IPv6 {})", {hdr.ipv6.srcAddr}); //Debug msg
    }
    
    table ipv4_blacklist { //Table with blacklsited ipv4 addresses
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            ipv4_block;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    table ipv6_blacklist { //Table with blacklsited ipv6 addresses
        key = {
            hdr.ipv6.srcAddr: lpm;
        }
        actions = {
            ipv6_block;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    action ipv4_valid(){ //Set the valid flag to true v4
    	validFlag = 1;
    	log_msg("Valid protocol (IPv4 {})", {hdr.ipv4.protocol}); //Debug msg
    }
    
    action ipv6_valid(){ //Set the valid flag to true v6
    	validFlag = 1;
    	log_msg("Valid protocol (IPv6 {})", {hdr.ipv6.nextHeader}); //Debug msg
    }
    
    table ipv4_protocol { //Static table for protocol checking v4
        key = {
            hdr.ipv4.protocol: exact;
        }
        actions = {
            ipv4_valid;
            NoAction;
        }
        
        const default_action = NoAction;
        const entries = { //ipv4_valid() for whitelisted protocols
        PROT_ICMP:		ipv4_valid();
        PROT_TCP:		ipv4_valid();
        PROT_UDP:		NoAction();
        	
        }
    }
    
    table ipv6_protocol { //Static table for protocol checking v6
        key = {
            hdr.ipv6.nextHeader: exact;
        }
        actions = {
            ipv6_valid;
            NoAction;
        }
        
        const default_action = NoAction;
        const entries = { //ipv6_valid() for whitelisted protocols
        PROT_ICMPv6:	ipv6_valid();
        PROT_TCP:		NoAction();
        PROT_UDP:		NoAction();
        	
        }
    }


    apply {
    	//First check if valid protocol
    	if (standard_metadata.parser_error != error.NoError) {
    			packet_drop(); //Drop packets if any error detected
    			exit;
		}
    
    	//Check if not over packet limit
    	bit<48> prevTime;
    	bit<48> curTime = standard_metadata.ingress_global_timestamp;
    	bit<48> packetCount;
    	regPrevTime.read(prevTime, 0);
		
    	if(curTime - prevTime > deltaTime || curTime < prevTime){
    		regPrevTime.write(0, curTime);
    		regPacketCount.write(0, 0);
    		//Reset the registers if timeframe is over or time overflow
    	}
    	else{
    		regPacketCount.read(packetCount, 0);
    		if(packetCount > packetLimit){
    			log_msg("Packet limit reached"); //Debug msg
    			packet_drop();
				exit;
    		}
    		else{
    			packetCount = packetCount + 1;
    			regPacketCount.write(0, packetCount);
    		}
    	}

		//Do appropriate type processing
        if (hdr.ipv4.isValid()) { //Do ipv4 processing if valid  
        		blackListFlag = 0;
        		validFlag = 0; //Ensure flags are set to 0
        		
        		ipv4_blacklist.apply(); //Check if address not blacklisted
        		if(blackListFlag == 1){
        			packet_drop();
        			exit;
        		}
        		
        		ipv4_protocol.apply(); //Check the protocol
            	if (validFlag == 1){
            		ipv4_lpm.apply(); //Forward if valid
            	}
            	else {
            		packet_drop(); //Drop otherwise
            	}
        } 
        else if (hdr.ipv6.isValid()) { //Do ipv6 processing if valid  
        		blackListFlag = 0;
        		validFlag = 0; //Ensure flags are set to 0
        		
        		ipv6_blacklist.apply(); //Check if address not blacklisted
        		if(blackListFlag == 1){
        			packet_drop();
        			exit;
        		}
        		
        		ipv6_protocol.apply(); //Check the protocol
            	if (validFlag == 1){
            		ipv6_lpm.apply(); //Forward if valid
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
        packet.emit(hdr.ipv6);
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
