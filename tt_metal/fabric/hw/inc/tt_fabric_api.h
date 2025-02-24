// SPDX-FileCopyrightText: © 2023 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "risc_attribs.h"
#include "dataflow_api.h"
#include "noc_overlay_parameters.h"
#include "ethernet/dataflow_api.h"
#include "tt_fabric.h"
#include "tt_fabric_interface.h"
#include "eth_chan_noc_mapping.h"

namespace tt::tt_fabric {

enum AsyncWriteMode : uint8_t {
    ADD_PR = 0x01,
    SEND_PR = 0x02,
    ADD_HEADER = 0x04,
    ADD_AND_SEND_PR = ADD_PR | SEND_PR,
    ALL = ADD_HEADER | ADD_PR | SEND_PR,
};

enum RoutingType : uint8_t {
    ROUTING_TABLE,
    ROUTER_XY,
};

inline uint32_t get_next_hop_router_noc_xy(
    volatile tt_l1_ptr fabric_pull_client_interface_t* client_interface,
    uint32_t routing_plane,
    uint32_t dst_mesh_id,
    uint32_t dst_dev_id) {
    ASSERT(routing_plane < client_interface->num_routing_planes);
    fabric_router_l1_config_t* routing_table = (fabric_router_l1_config_t*)client_interface->routing_tables_l1_offset;
    if (dst_mesh_id != routing_table[routing_plane].my_mesh_id) {
        uint32_t next_port = routing_table[routing_plane].inter_mesh_table.dest_entry[dst_mesh_id];
        return eth_chan_to_noc_xy[noc_index][next_port];
    } else {
        uint32_t next_port = routing_table[routing_plane].intra_mesh_table.dest_entry[dst_dev_id];
        return eth_chan_to_noc_xy[noc_index][next_port];
    }
}

inline void fabric_setup_pull_request(
    volatile tt_l1_ptr fabric_pull_client_interface_t* client_interface, uint32_t src_addr, uint32_t size) {
    uint32_t size_in_words = (size + PACKET_WORD_SIZE_BYTES - 1) >> 4;
    // TODO: Could return this value to the user and take this as an arg to avoid repeated lookup
    // Added here to avoid user having to declare globals
    uint64_t xy_local_addr = get_noc_addr(0);
    client_interface->local_pull_request.pull_request.wr_ptr = size_in_words;
    client_interface->local_pull_request.pull_request.rd_ptr = 0;
    client_interface->local_pull_request.pull_request.size = size;
    client_interface->local_pull_request.pull_request.buffer_size = size_in_words;
    client_interface->local_pull_request.pull_request.buffer_start = xy_local_addr + src_addr;
    client_interface->local_pull_request.pull_request.words_written = size_in_words;
    client_interface->local_pull_request.pull_request.words_read = 0;
    client_interface->local_pull_request.pull_request.ack_addr =
        xy_local_addr + (uint32_t)&client_interface->local_pull_request.pull_request.words_read;
    client_interface->local_pull_request.pull_request.flags = FORWARD;
}

template <RoutingType routing_type = RoutingType::ROUTER_XY>
inline void fabric_send_pull_request(
    volatile tt_l1_ptr fabric_pull_client_interface_t* client_interface,
    uint32_t routing,  // routing refers to the router noc xy to use when using ROUTER_XY,
                       // and the routing plane to use when using ROUTING_TABLE
    uint16_t dst_mesh_id,
    uint16_t dst_dev_id) {
    uint64_t router_addr;
    if constexpr (routing_type == RoutingType::ROUTING_TABLE) {
        router_addr = ((uint64_t)get_next_hop_router_noc_xy(client_interface, routing, dst_mesh_id, dst_dev_id) << 32) |
                      FABRIC_ROUTER_REQ_QUEUE_START;
    } else {
        router_addr = get_noc_addr_helper(routing, FABRIC_ROUTER_REQ_QUEUE_START);
    }
    tt_fabric_send_pull_request(router_addr, (volatile local_pull_request_t*)&client_interface->local_pull_request);
}

FORCE_INLINE void fabric_wait_for_pull_request_words_flushed(
    volatile tt_l1_ptr fabric_pull_client_interface_t* client_interface, uint32_t words) {
    while (client_interface->local_pull_request.pull_request.words_read < words) {
#pragma GCC unroll 4
        for (int i = 0; i < 4; i++) {
            asm("nop");
        }
    }
}

inline void fabric_wait_for_pull_request_bytes_flushed(
    volatile tt_l1_ptr fabric_pull_client_interface_t* client_interface, uint32_t size) {
    uint32_t size_in_words = (size + PACKET_WORD_SIZE_BYTES - 1) >> 4;
    fabric_wait_for_pull_request_words_flushed(client_interface, size_in_words);
}

inline void fabric_wait_for_pull_request_flushed(volatile tt_l1_ptr fabric_pull_client_interface_t* client_interface) {
    uint32_t words_written = client_interface->local_pull_request.pull_request.words_written;
    fabric_wait_for_pull_request_words_flushed(client_interface, words_written);
}

inline void fabric_async_write_add_header(
    uint32_t src_addr,  // source address in sender’s memory
    uint16_t dst_mesh_id,
    uint16_t dst_dev_id,
    uint64_t dst_addr,
    uint32_t size  // number of bytes to write to remote destination
) {
    packet_header_t* packet_header = (packet_header_t*)(src_addr);
    packet_header->routing.flags = FORWARD;
    packet_header->routing.packet_size_bytes = size;
    packet_header->routing.dst_mesh_id = dst_mesh_id;
    packet_header->routing.dst_dev_id = dst_dev_id;
    packet_header->session.command = ASYNC_WR;
    packet_header->session.target_offset_l = (uint32_t)dst_addr;
    packet_header->session.target_offset_h = dst_addr >> 32;
    tt_fabric_add_header_checksum(packet_header);
}

// Write packetized data over fabric to dst_mesh, dst_dev.
// Packet is at src_addr in sender L1.
template <AsyncWriteMode mode = AsyncWriteMode::ALL, RoutingType routing_type = RoutingType::ROUTER_XY>
inline void fabric_async_write(
    volatile tt_l1_ptr fabric_pull_client_interface_t* client_interface,
    uint32_t routing,   // routing refers to the router noc xy to use when using ROUTER_XY,
                        // and the routing plane to use when using ROUTING_TABLE
    uint32_t src_addr,  // source address in sender’s memory
    uint16_t dst_mesh_id,
    uint16_t dst_dev_id,
    uint64_t dst_addr,
    uint32_t size  // number of bytes to write to remote destination
) {
    if constexpr (mode & AsyncWriteMode::ADD_HEADER) {
        fabric_async_write_add_header(src_addr, dst_mesh_id, dst_dev_id, dst_addr, size);
    }

    if constexpr (mode & AsyncWriteMode::ADD_PR) {
        fabric_setup_pull_request(client_interface, src_addr, size);
    }

    if constexpr (mode & AsyncWriteMode::SEND_PR) {
        fabric_send_pull_request<routing_type>(client_interface, routing, dst_mesh_id, dst_dev_id);
    }
}

inline void fabric_async_write_multicast_add_header(
    uint32_t src_addr,  // source address in sender’s memory
    uint16_t dst_mesh_id,
    uint16_t dst_dev_id,
    uint64_t dst_addr,
    uint32_t size,  // number of bytes to write to remote destination
    uint16_t e_depth,
    uint16_t w_depth,
    uint16_t n_depth,
    uint16_t s_depth) {
    packet_header_t* packet_header = (packet_header_t*)(src_addr);
    packet_header->routing.flags = FORWARD | MCAST_DATA;
    packet_header->routing.packet_size_bytes = size;
    packet_header->routing.dst_mesh_id = dst_mesh_id;
    packet_header->routing.dst_dev_id = dst_dev_id;
    packet_header->session.command = ASYNC_WR;
    packet_header->session.target_offset_l = (uint32_t)dst_addr;
    packet_header->session.target_offset_h = dst_addr >> 32;
    packet_header->packet_parameters.mcast_parameters.east = e_depth;
    packet_header->packet_parameters.mcast_parameters.west = w_depth;
    packet_header->packet_parameters.mcast_parameters.north = n_depth;
    packet_header->packet_parameters.mcast_parameters.south = s_depth;
    tt_fabric_add_header_checksum(packet_header);
}
// Write packetized data over fabric to dst_mesh, dst_dev.
// Packet is at src_addr in sender L1.
template <AsyncWriteMode mode = AsyncWriteMode::ALL, RoutingType routing_type = RoutingType::ROUTER_XY>
inline void fabric_async_write_multicast(
    volatile tt_l1_ptr fabric_pull_client_interface_t* client_interface,
    uint32_t routing,   // routing refers to the router noc xy to use when using ROUTER_XY,
                        // and the routing plane to use when using ROUTING_TABLE
    uint32_t src_addr,  // source address in sender’s memory
    uint16_t dst_mesh_id,
    uint16_t dst_dev_id,
    uint64_t dst_addr,
    uint32_t size,  // number of bytes to write to remote destination
    uint16_t e_depth,
    uint16_t w_depth,
    uint16_t n_depth,
    uint16_t s_depth) {
    if constexpr (mode & AsyncWriteMode::ADD_HEADER) {
        fabric_async_write_multicast_add_header(
            src_addr, dst_mesh_id, dst_dev_id, dst_addr, size, e_depth, w_depth, n_depth, s_depth);
    }

    if constexpr (mode & AsyncWriteMode::ADD_PR) {
        fabric_setup_pull_request(client_interface, src_addr, size);
    }

    if constexpr (mode & AsyncWriteMode::SEND_PR) {
        fabric_send_pull_request<routing_type>(client_interface, routing, dst_mesh_id, dst_dev_id);
    }
}

inline void fabric_atomic_inc_add_header(
    uint32_t src_addr,  // source address in sender’s memory
    uint16_t dst_mesh_id,
    uint16_t dst_dev_id,
    uint64_t dst_addr,
    uint32_t atomic_inc,
    uint32_t wrap_boundary) {
    packet_header_t* packet_header = (packet_header_t*)(src_addr);
    packet_header->routing.flags = INLINE_FORWARD;
    packet_header->routing.packet_size_bytes = PACKET_HEADER_SIZE_BYTES;
    packet_header->routing.dst_mesh_id = dst_mesh_id;
    packet_header->routing.dst_dev_id = dst_dev_id;
    packet_header->session.command = ATOMIC_INC;
    packet_header->session.target_offset_l = (uint32_t)dst_addr;
    packet_header->session.target_offset_h = dst_addr >> 32;
    packet_header->packet_parameters.atomic_parameters.wrap_boundary = wrap_boundary;
    packet_header->packet_parameters.atomic_parameters.increment = atomic_inc;
    tt_fabric_add_header_checksum(packet_header);
}

// Write packetized data over fabric to dst_mesh, dst_dev.
// Packet is at src_addr in sender L1.
template <AsyncWriteMode mode = AsyncWriteMode::ALL, RoutingType routing_type = RoutingType::ROUTER_XY>
inline void fabric_atomic_inc(
    volatile tt_l1_ptr fabric_pull_client_interface_t* client_interface,
    uint32_t routing,   // routing refers to the router noc xy to use when using ROUTER_XY,
                        // and the routing plane to use when using ROUTING_TABLE
    uint32_t src_addr,  // source address in sender’s memory
    uint16_t dst_mesh_id,
    uint16_t dst_dev_id,
    uint64_t dst_addr,
    uint32_t atomic_inc,
    uint32_t wrap_boundary) {
    if constexpr (mode & AsyncWriteMode::ADD_HEADER) {
        fabric_atomic_inc_add_header(src_addr, dst_mesh_id, dst_dev_id, dst_addr, atomic_inc, wrap_boundary);
    }

    if constexpr (mode & AsyncWriteMode::ADD_PR) {
        fabric_setup_pull_request(client_interface, src_addr, PACKET_HEADER_SIZE_BYTES);
    }

    if constexpr (mode & AsyncWriteMode::SEND_PR) {
        fabric_send_pull_request<routing_type>(client_interface, routing, dst_mesh_id, dst_dev_id);
    }
}

inline void fabric_async_write_atomic_inc_add_header(
    uint32_t src_addr,  // source address in sender’s memory
    uint16_t dst_mesh_id,
    uint16_t dst_dev_id,
    uint64_t dst_write_addr,
    uint64_t dst_atomic_addr,
    uint32_t size,  // number of bytes to write to remote destination
    uint32_t atomic_inc) {
    packet_header_t* packet_header = (packet_header_t*)(src_addr);
    packet_header->routing.flags = FORWARD;
    packet_header->routing.packet_size_bytes = size;
    packet_header->routing.dst_mesh_id = dst_mesh_id;
    packet_header->routing.dst_dev_id = dst_dev_id;
    packet_header->session.command = ASYNC_WR | ATOMIC_INC;
    packet_header->session.target_offset_l = (uint32_t)dst_write_addr;
    packet_header->session.target_offset_h = dst_atomic_addr >> 32;
    packet_header->packet_parameters.async_wr_atomic_parameters.noc_xy = dst_atomic_addr >> 32;
    packet_header->packet_parameters.async_wr_atomic_parameters.l1_offset = (uint32_t)dst_atomic_addr;
    packet_header->packet_parameters.async_wr_atomic_parameters.increment = atomic_inc;
    tt_fabric_add_header_checksum(packet_header);
}

// Write packetized data over fabric to dst_mesh, dst_dev.
// Packet is at src_addr in sender L1.
template <AsyncWriteMode mode = AsyncWriteMode::ALL, RoutingType routing_type = RoutingType::ROUTER_XY>
inline void fabric_async_write_atomic_inc(
    volatile tt_l1_ptr fabric_pull_client_interface_t* client_interface,
    uint32_t routing,   // routing refers to the router noc xy to use when using ROUTER_XY,
                        // and the routing plane to use when using ROUTING_TABLE
    uint32_t src_addr,  // source address in sender’s memory
    uint16_t dst_mesh_id,
    uint16_t dst_dev_id,
    uint64_t dst_write_addr,
    uint64_t dst_atomic_addr,
    uint32_t size,  // number of bytes to write to remote destination
    uint32_t atomic_inc) {
    if constexpr (mode & AsyncWriteMode::ADD_HEADER) {
        fabric_async_write_atomic_inc_add_header(
            src_addr, dst_mesh_id, dst_dev_id, dst_write_addr, dst_atomic_addr, size, atomic_inc);
    }

    if constexpr (mode & AsyncWriteMode::ADD_PR) {
        fabric_setup_pull_request(client_interface, src_addr, size);
    }

    if constexpr (mode & AsyncWriteMode::SEND_PR) {
        fabric_send_pull_request<routing_type>(client_interface, routing, dst_mesh_id, dst_dev_id);
    }
}

template <RoutingType routing_type = RoutingType::ROUTER_XY>
inline void fabric_endpoint_init(
    volatile tt_l1_ptr fabric_pull_client_interface_t* client_interface, uint32_t outbound_eth_chan) {
    // TODO: Should not assume routing tables are immediately after the client interface
    // This should be a separate address we take in
    uint32_t routing_tables_offset = (uint32_t)client_interface + sizeof(fabric_pull_client_interface_t);

    zero_l1_buf((uint32_t*)client_interface, sizeof(fabric_pull_client_interface_t));
    client_interface->routing_tables_l1_offset = routing_tables_offset;
    client_interface->num_routing_planes = 1;

    if constexpr (routing_type == RoutingType::ROUTING_TABLE) {
        // read routing table
        uint64_t dest_addr = get_noc_addr_helper(
            eth_chan_to_noc_xy[noc_index][outbound_eth_chan], eth_l1_mem::address_map::FABRIC_ROUTER_CONFIG_BASE);
        noc_async_read_one_packet(dest_addr, routing_tables_offset, sizeof(fabric_router_l1_config_t));
        noc_async_read_barrier();
    }
}

}  // namespace tt::tt_fabric
