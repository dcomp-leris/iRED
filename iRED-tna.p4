/* -*- P4_16 -*- */
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROTO = 253;

const bit<32> MinTh = 280; // Min threshold for 64 packets of buffer size
const bit<32> MaxTh = 560; // Max threshold for 64 packets of buffer size


#define MAX_HOPS 10
#define PORTS 10

const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_NORMAL        = 0;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE  = 2;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_COALESCED     = 3;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC        = 4;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION   = 5;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT      = 6;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_v;
typedef bit<32> ip4Addr_v;
typedef bit<9>  egressSpec_v;

header ethernet_h {
    macAddr_v dstAddr;
    macAddr_v srcAddr;
    bit<16>   etherType;
}

header ipv4_h {
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
    ip4Addr_v srcAddr;
    ip4Addr_v dstAddr;
}


struct queue_metadata_t {
    @field_list(0)
    bit<32> output_port;
    bit<2>mirrorType;
}

struct metadata {
    queue_metadata_t    queue_metadata;
}

struct headers {
    ethernet_h         ethernet;
    ipv4_h             ipv4;
}



/*************************************************************************
*********************** I N G R E S S  ***********************************
*************************************************************************/

parser MyIngressParser(packet_in packet,
                out headers hdr,
                inout metadata ig_meta,
                inout ingress_intrinsic_metadata_t ig_standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            0: accept;
            default: accept;
        }
    } 
}   

control MyIngressDeparser(
    packet_out packet,
    inout headers ig_hdr,
    in metadata ig_meta,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_meta) {
    apply {
        packet.emit(ig_hdr.ethernet);
        packet.emit(ig_hdr.ipv4);                
    }
}

control MyIngress(inout headers ig_hdr,
                  inout metadata ig_meta,
                  inout ingress_intrinsic_metadata_t ig_standard_metadata,
                  inout ingress_intrinsic_metadata_for_parser_t ig_prsr_meta,
                  inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_meta,
                  inout ingress_intrinsic_metadata_for_tm_t ig_tm_meta) {
    
    register<bit<1>> (PORTS) flagtoDrop_reg; // Register ON/OFF drop action
    counter(4, CounterType.packets) forwardingPkt; // Counter forwarding packets
    counter(4, CounterType.packets) dropPkt; // Counter packets dropped by RED
    counter(4, CounterType.packets) dropRecirc; // Counter recirculated
    
    
    // Action to drop recirculate pkts
    action drop() {
        dropRecirc.count(ig_meta.queue_metadata.output_port);
        mark_to_drop(ig_standard_metadata);
    }

    // Action to drop pkts
    action drop_count() {
        dropPkt.count((bit<32>)ig_standard_metadata.egress_spec);
        mark_to_drop(ig_standard_metadata);
    }
    
    action ipv4_forward(macAddr_v dstAddr, egressSpec_v port) {
        ig_standard_metadata.egress_spec = port;
        ig_hdr.ethernet.srcAddr = ig_hdr.ethernet.dstAddr;
        ig_hdr.ethernet.dstAddr = dstAddr;
        ig_hdr.ipv4.ttl = ig_hdr.ipv4.ttl - 1;
        forwardingPkt.count((bit<32>)ig_standard_metadata.egress_spec);
    }

    table ipv4_lpm {
        key = {
            ig_hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    
    apply {

        if (ig_standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC) {
            flagtoDrop_reg.write(ig_meta.queue_metadata.output_port,1); 
            drop();
        }
        else {

            ipv4_lpm.apply();
        
            bit<1> flag;
        
            flagtoDrop_reg.read(flag,(bit<32>)ig_standard_metadata.egress_spec);

            if (flag == 1){            
                flagtoDrop_reg.write((bit<32>)ig_standard_metadata.egress_spec,0);
                drop_count();
            }

        }
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

parser MyEgressParser(
        packet_in pkt,
        out headers eg_hdr,
        out metadata eg_meta,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        transition accept;
    }
}

control MyEgressDeparser(
    packet_out packet,
    in headers hdr,
    in metadata eg_meta,
    in egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_meta) {
    Checksum() ipv4_csum;
    apply {
        if (hdr.ipv4.isValid()) {
        hdr.ipv4.hdrChecksum = ipv4_csum.update ({
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
            hdr.ipv4.dstAddr});
        }
        Mirror() mirror;
        if(eg_intr_dprs_meta.mirror_type == 1 {
            mirror.emit(eg_meta.queue_metadata.output_port)
        }
        if(eg_intr_dprs_meta.mirror_type == 2 {
            mirror.emit(eg_meta.queue_metadata.output_port)
        }
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);                
    }

}



control MyEgress(inout headers eg_hdr,
                 inout metadata eg_meta,
                 in egress_intrinsic_metadata_t eg_standard_metadata,
                 inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_meta) {

        register<bit<10>> (1) dp_r; // Register to save drop probability        
        register<bit<32>>(PORTS) oldQdepth_reg; //Register to save old queue depth           
        counter(4, CounterType.packets) recirc; // Counter recirculate pkts
        counter(4, CounterType.packets) cloneCount; // Counter clone pkts
        
        // Send again the packet through both pipelines
        action recirculate_packet(){
            eg_intr_dprs_meta.resubmit_type = 2;
            recirculate_preserving_field_list(0);
            recirc.count(eg_meta.queue_metadata.output_port);
        }

        action clonePacket(){
            eg_intr_dprs_meta.mirror_type = 1;
            //clone_preserving_field_list(CloneType.E2E ,eg_meta.queue_metadata.output_port,0);
            cloneCount.count(eg_meta.queue_metadata.output_port);
        }

        apply {
            
            // Check IF is a clone pkt generated in the egress
            if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE) {
                eg_meta.queue_metadata.output_port = (bit<32>)standard_metadata.egress_port;
                recirculate_packet();
            } 
            else {

                bit<32> qdepth = (bit<32>)standard_metadata.enq_qdepth; // Get queue depth after TM
            
                bit<32> oldQdepth; //Old Qdepth  
                        
                oldQdepth_reg.read(oldQdepth, (bit<32>)standard_metadata.egress_port); // Read avg_queue register and save in oldQdepth
                oldQdepth_reg.write((bit<32>)standard_metadata.egress_port, qdepth);
            
                // WRED -> avg_WRED = o * (1 - 2^-n) + c * (2^-n)
                // where n is the user-configurable exponential weight factor, 
                // o is the old average and c is the current queue size. 
                // The previous average is more important for high values of n. Peaks and lows in 
                // queue size are smoothed by a high value. For low values of n, the average queue 
                // size is close to the current queue size.
                // We use n = 1. This makes the equation read as follows: New average = (Old_average * (1- 0.5)) + (Current_Q_depth * 0.5)
                // https://www.ccexpert.us/traffic-shaping-2/random-early-detection-red-1.html

                bit<32> new_avg = oldQdepth*5 + qdepth*5 ; //multiplied by 10;                     

                if (new_avg >= MinTh && new_avg <= MaxTh) {

                    bit<10> drop_random_temp;
                    dp_r.read(drop_random_temp,0);
                            
                    bit<10> a = 1;
                    bit<10> drop_prob = a + 1;
                    dp_r.write(0,drop_prob);
                            
                    bit<10> rand_val;
                    random(rand_val, 0, 511);
                            
                    if (drop_prob > rand_val){
                        eg_meta.queue_metadata.output_port = (bit<32>)standard_metadata.egress_port;
                        clonePacket();
                    }
                }
                        
                if (new_avg > MaxTh) {
                    eg_meta.queue_metadata.output_port = (bit<32>)standard_metadata.egress_port;
                    clonePacket();
                }

            }             
                 
        }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

Pipeline(
MyIngressParser(),
MyIngress(),
MyIngressDeparser(),
MyEgressParser(),
MyEgress(),
MyEgressDeparser()) pipe;

Switch(pipe) main;

