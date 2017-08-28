/*
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
 */

#include "includes/headers.p4"
#include "includes/parser.p4"

primitive_action set_tdelta();

/*
 * not INT case, we just drop and count
 */

counter not_int_counter {
    type : packets;
    instance_count : 1;
}

action do_not_int_drop() {
    count(not_int_counter, 0);
    drop();
}

table tbl_not_int_drop {
    actions {
        do_not_int_drop;
    }
}

action do_forward(espec)
{
    modify_field(standard_metadata.egress_spec, espec);
    add_to_field(int_header.total_hop_cnt, 1);
}

action do_drop() {
    drop();
}

table tbl_forward {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        do_forward;
        do_drop;
    }
}

control ingress
{
    if (not valid(int_header)) {
        apply(tbl_not_int_drop);
    } else {
        apply(tbl_forward);
    }
}

/*
 * Egress INT processing
 */

/* Instr Bit 0 */
action int_set_header_0() { //switch_id
    add_header(int_switch_id_header);
    modify_field(int_switch_id_header.switch_id, 0xcafe);
    add_to_field(vxlan_gpe_int_header.len, 1);
}

/* Instr Bit 1 */
action int_set_header_1() { //ingress_port_id
#ifdef INT_TO_SPEC
    add_header(int_ingress_port_id_header);
    modify_field(int_ingress_port_id_header.ingress_port_id_1, 0);
    modify_field(int_ingress_port_id_header.ingress_port_id_0,
                 standard_metadata.ingress_port);
    add_to_field(vxlan_gpe_int_header.len, 1);
#else
    add_header(int_ingress_ts);
    modify_field(int_ingress_ts.value, intrinsic_metadata.ingress_global_tstamp);
    add_to_field(vxlan_gpe_int_header.len, 1);
#endif
}

/* Instr Bit 2 */
action int_set_header_2() { //hop_latency
#ifdef INT_TO_SPEC
    add_to_field(vxlan_gpe_int_header.len, 1);
    add_header(int_hop_latency_header);
#else
    add_to_field(vxlan_gpe_int_header.len, 1);
    add_header(int_egress_ts);
#endif
}

/* Instr Bit 3 */
action int_set_header_3() { //q_occupancy
    add_header(int_q_occupancy_header);
    modify_field(int_q_occupancy_header.q_occupancy1, 0x7f);
    modify_field(int_q_occupancy_header.q_occupancy0, 0xffffff);
    add_to_field(vxlan_gpe_int_header.len, 1);
}

/* Instr Bit 4 */
action int_set_header_4() { //ingress_tstamp
    add_header(int_ingress_tstamp_header);
    modify_field(int_ingress_tstamp_header.ingress_tstamp,
                 intrinsic_metadata.ingress_global_tstamp);
    add_to_field(vxlan_gpe_int_header.len, 1);
}
/* Instr Bit 5 */
action int_set_header_5() { //egress_port_id
    add_header(int_egress_port_id_header);
    modify_field(int_egress_port_id_header.egress_port_id,
                    standard_metadata.egress_port);
    add_to_field(vxlan_gpe_int_header.len, 1);
}

/* Instr Bit 6 */
action int_set_header_6() { //q_congestion
    add_header(int_q_congestion_header);
    modify_field(int_q_congestion_header.q_congestion, 0x7FFFFFFF);
    add_to_field(vxlan_gpe_int_header.len, 1);
}
/* Instr Bit 7 */
action int_set_header_7() { //egress_port_tx_utilization
    add_header(int_egress_port_tx_utilization_header);
    modify_field(int_egress_port_tx_utilization_header.egress_port_tx_utilization, 0x7FFFFFFF);
    add_to_field(vxlan_gpe_int_header.len, 1);
}

/*
 * BOS
 */

action int_set_bos_0() {
    modify_field(int_switch_id_header.bos, 1);
}

action int_set_bos_1() {
#ifdef INT_TO_SPEC
    modify_field(int_ingress_port_id_header.bos, 1);
#else
    modify_field(int_ingress_ts.bos, 1);
#endif
}

action int_set_bos_2() {
#ifdef INT_TO_SPEC
    modify_field(int_hop_latency_header.bos, 1);
#else
    modify_field(int_egress_ts.bos, 1);
#endif
}

action int_set_bos_3() {
    modify_field(int_q_occupancy_header.bos, 1);
}

action int_set_bos_4() {
    modify_field(int_ingress_tstamp_header.bos, 1);
}

action int_set_bos_5() {
    modify_field(int_egress_port_id_header.bos, 1);
}

action int_set_bos_6() {
    modify_field(int_q_congestion_header.bos, 1);
}

action int_set_bos_7() {
    modify_field(int_egress_port_tx_utilization_header.bos, 1);
}

action update_egress_tstamp() {
    set_tdelta();
#ifdef INT_TO_SPEC
    modify_field(int_hop_latency_header.hop_latency, meta.tdelta);
#else
    modify_field(int_egress_ts.value, meta.tdelta);
#endif
}

table int_inst_0 {
    actions {
        int_set_header_0;
    }
}

table int_inst_1 {
    actions {
        int_set_header_1;
    }
}

table int_inst_2 {
    actions {
        int_set_header_2;
    }
}

table int_inst_3 {
    actions {
        int_set_header_3;
    }
}

table int_inst_4 {
    actions {
        int_set_header_4;
    }
}

table int_inst_5 {
    actions {
        int_set_header_5;
    }
}

table int_inst_6 {
    actions {
        int_set_header_6;
    }
}

table int_inst_7 {
    actions {
        int_set_header_7;
    }
}

table int_bos_0 {
    actions {
        int_set_bos_0;
    }
}

table int_bos_1 {
    actions {
        int_set_bos_1;
    }
}

table int_bos_2 {
    actions {
        int_set_bos_2;
    }
}

table int_bos_3 {
    actions {
        int_set_bos_3;
    }
}

table int_bos_4 {
    actions {
        int_set_bos_4;
    }
}

table int_bos_5 {
    actions {
        int_set_bos_5;
    }
}

table int_bos_6 {
    actions {
        int_set_bos_6;
    }
}

table int_bos_7 {
    actions {
        int_set_bos_7;
    }
}

table int_egress_tstamp {
    actions {
        update_egress_tstamp;
    }
}


control egress
{
    if ((int_header.instruction_mask_0003 & 0x8) != 0)
        apply(int_inst_0);
    if ((int_header.instruction_mask_0003 & 0x4) != 0)
        apply(int_inst_1);
    if ((int_header.instruction_mask_0003 & 0x2) != 0)
        apply(int_inst_2);
    if ((int_header.instruction_mask_0003 & 0x1) != 0)
        apply(int_inst_3);
    if ((int_header.instruction_mask_0407 & 0x8) != 0)
        apply(int_inst_4);
    if ((int_header.instruction_mask_0407 & 0x4) != 0)
        apply(int_inst_5);
    if ((int_header.instruction_mask_0407 & 0x2) != 0)
        apply(int_inst_6);
    if ((int_header.instruction_mask_0407 & 0x1) != 0)
        apply(int_inst_7);

    if (meta.int_inst_cnt == 0) {
        // insert the BOS
        if ((int_header.instruction_mask_0407 & 0x1) != 0) {
            apply(int_bos_7);
        } else if ((int_header.instruction_mask_0407 & 0x2) != 0) {
            apply(int_bos_6);
        } else if ((int_header.instruction_mask_0407 & 0x4) != 0) {
            apply(int_bos_5);
        } else if ((int_header.instruction_mask_0407 & 0x8) != 0) {
            apply(int_bos_4);
        } else if ((int_header.instruction_mask_0003 & 0x1) != 0) {
            apply(int_bos_3);
        } else if ((int_header.instruction_mask_0003 & 0x2) != 0) {
            apply(int_bos_2);
        } else if ((int_header.instruction_mask_0003 & 0x4) != 0) {
            apply(int_bos_1);
        } else if ((int_header.instruction_mask_0003 & 0x8) != 0) {
            apply(int_bos_0);
        }
    }

#ifdef INT_TO_SPEC
    if (valid(int_hop_latency_header)) {
        apply(int_egress_tstamp);
    }
#else
    if (valid(int_egress_ts)) {
        apply(int_egress_tstamp);
    }
#endif
}
