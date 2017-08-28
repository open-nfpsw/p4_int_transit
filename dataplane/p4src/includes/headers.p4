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
 * Header definitions for P4 INT transit, based on Barefoot's p4 switch defines
 */

header_type meta_t {
    fields {
        tdelta : 32;
        int_inst_cnt : 16;
    }
}

header_type intrinsic_metadata_t {
    fields {
        ingress_global_tstamp : 32;
    }
}

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16;
        checksum : 16;
    }
}

header_type vxlan_gpe_t {
    fields {
        flags : 8;
        reserved : 16;
        next_proto : 8;
        vni : 24;
        reserved2 : 8;
    }
}

header_type vxlan_gpe_int_header_t {
    fields {
        int_type    : 8;
        rsvd        : 8;
        len         : 8;
        next_proto  : 8;
    }
}

// INT headers
header_type int_header_t {
    fields {
        ver                     : 2;
        rep                     : 2;
        c                       : 1;
        e                       : 1;
        rsvd1                   : 5;
        ins_cnt                 : 5;
        max_hop_cnt             : 8;
        total_hop_cnt           : 8;
        instruction_mask_0003   : 4;   // split the bits for lookup
        instruction_mask_0407   : 4;
        instruction_mask_0811   : 4;
        instruction_mask_1215   : 4;
        rsvd2                   : 16;
    }
}

// INT meta-value headers - different header for each value type
header_type int_switch_id_header_t {
    fields {
        bos                 : 1;
        switch_id           : 31;
    }
}

#ifdef INT_TO_SPEC
header_type int_ingress_port_id_header_t {
    fields {
        bos                 : 1;
        ingress_port_id_1   : 15;
        ingress_port_id_0   : 16;
    }
}

header_type int_hop_latency_header_t {
    fields {
        bos                 : 1;
        hop_latency         : 31;
    }
}
#else
header_type int_ingress_ts_t {
    fields {
        bos                 : 1;
        value               : 31;
    }
}

header_type int_egress_ts_t {
    fields {
        bos                 : 1;
        value               : 31;
    }
}
#endif

header_type int_q_occupancy_header_t {
    fields {
        bos                 : 1;
        q_occupancy1        : 7;
        q_occupancy0        : 24;
    }
}

header_type int_ingress_tstamp_header_t {
    fields {
        bos                 : 1;
        ingress_tstamp      : 31;
    }
}

header_type int_egress_port_id_header_t {
    fields {
        bos                 : 1;
        egress_port_id      : 31;
    }
}

header_type int_q_congestion_header_t {
    fields {
        bos                 : 1;
        q_congestion        : 31;
    }
}

header_type int_egress_port_tx_utilization_header_t {
    fields {
        bos                         : 1;
        egress_port_tx_utilization  : 31;
    }
}
