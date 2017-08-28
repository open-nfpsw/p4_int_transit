/*
 * Copyright 2013-present Barefoot Networks, Inc.
 * Copyright (C) 2017, Netronome Systems, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 * Parser for INT transit; based on Barefoot's P4 switch parser
 */

metadata meta_t meta;
metadata intrinsic_metadata_t intrinsic_metadata;

parser start {
    return parse_ethernet;
}

/*
 * Ethernet
 */

#define ETHERTYPE_IPV4 0x0800

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default : ingress;
    }
}

/*
 * IPv4
 */

#define IP_PROTOCOLS_IPHL_UDP          0x511

header ipv4_t ipv4;

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum if (ipv4.ihl == 5);
    update ipv4_checksum if (ipv4.ihl == 5);
}

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.fragOffset, latest.ihl, latest.protocol) {
        IP_PROTOCOLS_IPHL_UDP : parse_udp;
        default: ingress;
    }
}

/*
 * UDP
 */

#define UDP_PORT_VXLAN_GPE             4790

header udp_t udp;

parser parse_udp {
    extract(udp);

    return select(latest.dstPort) {
        UDP_PORT_VXLAN_GPE : parse_vxlan_gpe;
        default: ingress;
    }

}

/*
 * INT
 */

#define VXLAN_GPE_NEXT_PROTO_INT        0x05 mask 0xff

header vxlan_gpe_t vxlan_gpe;

parser parse_vxlan_gpe {
    extract(vxlan_gpe);
    return select(vxlan_gpe.next_proto) {
        VXLAN_GPE_NEXT_PROTO_INT : parse_gpe_int_header;
        default : ingress;
    }
}

header int_header_t                             int_header;
header int_switch_id_header_t                   int_switch_id_header;
#ifdef INT_TO_SPEC
header int_ingress_port_id_header_t             int_ingress_port_id_header;
header int_hop_latency_header_t                 int_hop_latency_header;
#else
header int_ingress_ts_t                         int_ingress_ts;
header int_egress_ts_t                          int_egress_ts;
#endif
header int_q_occupancy_header_t                 int_q_occupancy_header;
header int_ingress_tstamp_header_t              int_ingress_tstamp_header;
header int_egress_port_id_header_t              int_egress_port_id_header;
header int_q_congestion_header_t                int_q_congestion_header;
header int_egress_port_tx_utilization_header_t  int_egress_port_tx_utilization_header;
header vxlan_gpe_int_header_t                   vxlan_gpe_int_header;

parser parse_gpe_int_header {
    // GPE uses a shim header to preserve the next_protocol field
    extract(vxlan_gpe_int_header);
    return parse_int_header;
}

parser parse_int_header {
    extract(int_header);
    set_metadata(meta.int_inst_cnt, int_header.total_hop_cnt);
    return select (latest.rsvd1, latest.total_hop_cnt) {
        0 mask 0: ingress;
        // never transition to the following state
        default: parse_all_int_meta_values_dummy;
    }
}

parser parse_all_int_meta_values_dummy {
    // bogus state.. just extract all possible int headers in the
    // correct order to build
    // the correct parse graph for deparser (while adding headers)
    extract(int_switch_id_header);
#ifdef INT_TO_SPEC
    extract(int_ingress_port_id_header);
    extract(int_hop_latency_header);
#else
    extract(int_ingress_ts);
    extract(int_egress_ts);
#endif
    extract(int_q_occupancy_header);
    extract(int_ingress_tstamp_header);
    extract(int_egress_port_id_header);
    extract(int_q_congestion_header);
    extract(int_egress_port_tx_utilization_header);
    return ingress;
}
