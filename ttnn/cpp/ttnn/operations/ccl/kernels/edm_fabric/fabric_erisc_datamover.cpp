// SPDX-FileCopyrightText: © 2024 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#include <array>
#include <cstddef>
#include <cstdint>

#include "dataflow_api.h"
#include "tt_metal/hw/inc/ethernet/dataflow_api.h"
#include "cpp/ttnn/operations/ccl/kernels/edm/edm_handshake.hpp"
#include "cpp/ttnn/operations/ccl/kernels/edm_fabric/edm_fabric_worker_adapters.hpp"
#include "cpp/ttnn/operations/ccl/kernels/edm_fabric/fabric_edm_packet_header.hpp"
#include "cpp/ttnn/operations/ccl/kernels/edm_fabric/fabric_edm_packet_header_validate.hpp"
#include "cpp/ttnn/operations/ccl/kernels/edm_fabric/fabric_edm_packet_transmission.hpp"
#include "cpp/ttnn/operations/ccl/kernels/edm_fabric/fabric_erisc_datamover_channels.hpp"
#include "cpp/ttnn/operations/ccl/shared_with_host/hetergeneous_data_structs.hpp"

#include "noc_overlay_parameters.h"

#include "ttnn/cpp/ttnn/operations/ccl/kernels/edm_fabric/edm_fabric_counters.hpp"


using ttnn::ccl::WorkerXY;

/*

The fabric Erisc Data Mover (EDM) is a component that can be used to build *very* simple linear topology fabrics.
One of these EDMs can be instantiated on each ethernet link. It is built from 3 "channels" (though the definition
of channel here is a little loose since two of the 3 will merge traffic, so this setup could be interpreted as a
two channel setup.). This EDM implements packet based packets only - concepts like sockets are not supported.

## EDM Structure

There are two sender channels and one receiver channel. "Sender" and "receiver" are relative to the Ethernet link,
not the chip. Sender sends over the link and receiver receives from the link.

Each sender channel serves a different purpose:
- Sender channel 0 : Accepts packets from a workers on the local chip
- Sender channel 1: accepts packets from an upstream EDM (i.e. an upstream
  EDM receiver channel on the same chip but different core)

The receiver channel accepts packets from the Ethernet link and can do one (or both) of:
- Write the packet to local chhip if it is the intended destination (unicast or mcast)
- Forward the packet to the next chip in the line if:
  - Unicast and not the target chip
  - Multicast and this chip is in the multicast target range

Sender channels will merge traffic into the remote EDM's receiver channel.

Below is a diagram that shows how EDMs can be connected over an ethernet link. In this case, the two
EDM kernels are run on separate, but connected ethernet link cores.

 ┌───────────────────────┐           ┌───────────────────────┐
 │    Sender Channel 0   │           │    Receiver Channel   │
 │   ┌────────────────┐  │           │   ┌────────────────┐  │
 │   │                ┼──┼───┬───────┼───►                │  │
 │   │                │  │   │       │   │                │  │
 │   └────────────────┘  │   │       │   └────────────────┘  │
 │    Sender Channel 1   │   │       │    Sender Channel 1   │
 │   ┌────────────────┐  │   │       │   ┌────────────────┐  │
 │   │                ┼──┼───┘       │   │                │  │
 │   │                │  │         ┌─┼───┼                │  │
 │   └────────────────┘  │         │ │   └────────────────┘  │
 │    Receiver Channel   │         │ │    Sender Channel 0   │
 │   ┌────────────────┐  │         │ │   ┌────────────────┐  │
 │   │                │  │         │ │   │                │  │
 │   │                ◄──┼─────────┴─┼───┼                │  │
 │   └────────────────┘  │           │   └────────────────┘  │
 │                       │           │                       │
 │                       │           │                       │
 └───────────────────────┘           └───────────────────────┘


## Building a "Fabric"

At present, only linear topologies are supported, and one per ethernet link along that given line.
Below shows the intended connectivity of EDMs across chips in a hypothetical 3-chip fabric. For longer
lines, the pattern would be extended.

           CHIP 0                              CHIP 1                             CHIP 2
     ┌─────────────────┐                ┌─────────────────┐                ┌─────────────────┐
     │                 │                │                 │                │                 │
┌────┴─────┐ ▲   ┌─────┴────┐      ┌────┴─────┐ ▲   ┌─────┴────┐      ┌────┴─────┐ ▲   ┌─────┴────┐
│   EDM    │ │   │   EDM    │      │   EDM    │ │   │   EDM    │      │   EDM    │ │   │   EDM    │
│ ┌──────┐ │ │   │ ┌──────┐ │      │ ┌──────┐ │ │   │ ┌──────┐ │      │ ┌──────┐ │ │   │ ┌──────┐ │
│ │ Rx   ┼─┼─┴───┼─► S1   ┼─┼─┬────┼─► Rx   ┼─┼─┴───┼─► S1   ┼─┼┬─────┼─► Rx   ┼─┼─┘   | | S1   │ │
│ └──────┘ │     │ └──────┘ │ │    │ └──────┘ │     │ └──────┘ ││     │ └──────┘ │     │ └──────┘ │
│ ┌──────┐ │     │ ┌──────┐ │ │    │ ┌──────┐ │     │ ┌──────┐ ││     │ ┌──────┐ │     │ ┌──────┐ │
│ │ S0   ◄─┼──┬──┼─► S0   ┼─┼─┘   ┌┼─┼ S0   ◄─┼──┬──┼─► S0   ┼─┼┘    ┌┼─┼ S0   ◄─┼──┬──┼─► S0   │ │
│ └──────┘ │  │  │ └──────┘ │     ││ └──────┘ │  │  │ └──────┘ │     ││ └──────┘ │  │  │ └──────┘ │
│ ┌──────┐ │  │  │ ┌──────┐ │     ││ ┌──────┐ │  │  │ ┌──────┐ │     ││ ┌──────┐ │  │  │ ┌──────┐ │
│ │ S1   | |  │ ┌┼─┼ Rx   ◄─┼─────┴┼─┼ S1   ◄─┼─┐│ ┌┼─┼ Rx   ◄─┼─────┴┼─┼ S1   ◄─┼─┐│ ┌┼─┼ Rx   │ │
│ └──────┘ │  | |│ └──────┘ │      │ └──────┘ │ └┼─┤│ └──────┘ │      │ └──────┘ │ └┼─┤│ └──────┘ │
└────┬─────┘  │ │└─────┬────┘      └────┬─────┘  │ │└─────┬────┘      └────┬─────┘  │ │└─────┬────┘
     │          ▼      │                │          ▼      │                │          ▼      │
     └─────────────────┘                └─────────────────┘                └─────────────────┘


## Connecting Workers to Channels

As mentioned, only one worker can push to a given EDM sender channel at a time. In order to send to an EDM
sender channel, the worker must establish a connection. The connection protocol is as follows and is started
by the worker (the EDM is a slave in this protocol).

*NOTE*: If multiple workers try to connect to the same EDM sender channel at the same time, the behavior is undefined.
*NOTE*: Additionally, if a worker pushes packets to a channel it isn't connected to, behaviour is undefined.
*NOTE*: Undefined == likely hang

The `WorkerToFabricEdmSender` from `ttnn/cpp/ttnn/operations/ccl/kernels/edm_fabric/edm_fabric_worker_adapters.hpp`
provides an implementation of the connection protocol. `WorkerToFabricEdmSender` also acts as a wrapper around that
protocol so workers can simply call `open()` to execute the connection protocol without having to manually reimplement
for each kernel.

### Protocol
Worker:
- Read from EDM sender channel buffer_index address
  - Required so that the worker knows where to write its first packet (since the channel may already contain packets from
    a previous connection)
- Write worker core X/Y (NOC 0 based)
- Write worker flow control semaphore L1 address

EDM Sender Channel:
- Check local connection valid semaphore for new established connection
  - When the connection semaphore indicates an active connection, the channel assumes all other relevant fields were
    correctly populated by the worker:
    - Worker core_x (on NOC 0)
    - Worker core_y (on NOC 0)
    - Worker flow control semaphore L1 address


## Tearing Down Connections

Every worker is required to explicitly teardown its connection with the EDM before terminating. To do this, the worker
must simply write a `0` to the EDM sender channel's connection semaphore address. As long as the worker has sent all
of its packets to the EDM before this, then the EDM will guarantee to forward the messages correctly.

At this point, it is safe for another kernel to establish a connection.

## Packet Structure

Workers are responsible for populating packet headers before sending to the EDM. The packet header structure is defined
in `ttnn/cpp/ttnn/operations/ccl/kernels/edm_fabric/fabric_edm_packet_header.hpp`.

## Channel structure

Each EDM channel is built from one or more buffers. Each buffer is the same size and can hold atmost one packet.
Neighbouring packets occupy nehighouring buffers - with the exception of the last buffer index. The next packet after a write
into the last buffer index will wrap around to the first buffer index. Even if packets do not occupy the full buffer, subsequent
packets will always be written into the next logical buffer. A gap will exist in memory but the EDM will not send that padded data
(unless it is more performant - which is possible in some special cases)

 Example channel with 8 buffers
┌───────┬───────┬───────┬───────┬───────┬───────┬───────┬───────┐
│       │       │       │       │       │       │       │       │
│       │       │       │       │       │       │       │       │
└───────┴───────┴───────┴───────┴───────┴───────┴───────┴───────┘
 buf 0   buf 1   buf 2   buf 3   buf 4   buf 5   buf 6   buf 7


Here we have an example of a channel with 4 buffers, filled with some number of packets. Each packet is a different size.
Packets 0, 2, and 3 are smaller than the full buffer size, while packet 1 is the full buffer size.

┌───────────────┬───────────────┬───────────────┬───────────────┐
│H|Payload| / / │H|Payload      │H|Pyld| / / / /│H|Payload  |/ /│
│ |       |/ / /│ |             │ |    |/ / / / │ |         | / │
└───────────────┴───────────────┴───────────────┴───────────────┘
  buf 0           buf 1           buf 2           buf 3




## Sending Packets
Sending a packet is done as follows:

1) Worker waits for flow control semaphore increment from EDM sender channel
  - Indicates there is space at the next buffer index for a packet
2) Worker performs a noc write of its packet to the EDM sender channel at the buffer index

*NOTE*: !!!ALL PACKETS MUST CONTAIN DESTINATION NOC X/Y AS NOC 0 COORDINATES, REGARDLESS OF THE `noc_index` OF THE SENDER!!!


## EDM <-> EDM Channel Flow Control
The flow control protocol between EDM channels is built on a rd/wr ptr based protocol where pointers are
to buffer slots within the channel (as opposed so something else like byte or word offset). Ptrs are
free to advance independently from each other as long as there is no overflow or underflow.

The flow control is implemented through the use of several stream registers: one per conceptual pointer being tracked.
In total there are 5 such counters:
1) to receiver channel packets sent
  - Incremented by sender (via eth_reg_write) by the number of buffer slots written. In practice, this means it is
    incremented once per packet
2) to sender 0 packets acked
  - Incremented by receiver for every new packet from channel 0 that it sees
3) to sender 1 packets acked
  - Incremented by receiver for every new packet from channel 1 that it sees
4) to sender 0 packets completed
  - Incremented by receiver for every packet from channel 0 that it completes processing for
5) to sender 1 packets completed
  - Incremented by receiver for every packet from channel 1 that it completes processing for

See calls to `increment_local_update_ptr_val`, `remote_update_ptr_val`, `init_ptr_val` for more on implementation.

### Sender Channel Flow Control
Both sender channels share the same flow control view into the receiver channel. This is because both channels
write to the same receiver channel.
* wrptr:
  * points to next buffer slot to write to into the remote (over Ethernet) receiver channel.
  * leads other pointers
  * writer updates for every new packet
  * `has_data_to_send(): local_wrptr != remote_sender_wrptr`
* ackptr
  * trails `wrptr`
  * advances as the channel receives acknowledgements from the receiver
    * as this advances, the sender channel can notify the upstream worker of additional space in sender channel buffer
* completion_ptr:
  * trails `local_wrptr`
  * "rdptr" from remote sender's perspective
  * advances as packets completed by receiver
    * as this advances, the sender channel can write additional packets to the receiver at this slot

### Receiver Channel Flow Control
* ackptr/rdptr:
  * leads all pointers
  * indicates the next buffer slot we expect data to arrive (from remote sender) at
    * advances as packets are received (and acked)
  * make sure not to overlap completion pointer
* wr_sent_ptr:
  * trails `ackptr`
  * indicates the buffer slot currently being processed, written out
    * advances after all forwding writes (to noc or downstream EDM) are initiated
* wr_flush_ptr:
  * trails `wr_sent_ptr`
  * advances as writes are flushed
* completion_ptr:
  * trails `wr_flush_ptr`
  * indicates the next receiver buffer slot in the receiver channel to send completion acks for
*/


////////////////////////////////////////////////
// Data structures, types, enums, and constants
////////////////////////////////////////////////


// senders update this stream
static constexpr uint32_t to_receiver_pkts_sent_id = 0;
// receivers updates the reg on this stream
static constexpr uint32_t to_sender_0_pkts_acked_id = 1;
// receivers updates the reg on this stream
static constexpr uint32_t to_sender_1_pkts_acked_id = 2;
// receivers updates the reg on this stream
static constexpr uint32_t to_sender_0_pkts_completed_id = 3;
// receivers updates the reg on this stream
static constexpr uint32_t to_sender_1_pkts_completed_id = 4;

// This will be an atomic register read to the register
template <uint32_t stream_id>
int32_t get_ptr_val() {
    return NOC_STREAM_READ_REG(stream_id, STREAM_REMOTE_DEST_BUF_SPACE_AVAILABLE_REG_INDEX);
    constexpr uint32_t addr = STREAM_REG_ADDR(stream_id, STREAM_REMOTE_DEST_BUF_SPACE_AVAILABLE_REG_INDEX);
    return *reinterpret_cast<volatile uint32_t*>(addr);
}
int32_t get_ptr_val(uint8_t stream_id) {
    return NOC_STREAM_READ_REG(stream_id, STREAM_REMOTE_DEST_BUF_SPACE_AVAILABLE_REG_INDEX);
    const uint32_t addr = STREAM_REG_ADDR(stream_id, STREAM_REMOTE_DEST_BUF_SPACE_AVAILABLE_REG_INDEX);
    return *reinterpret_cast<volatile uint32_t*>(addr);
}

// Writing to this register will leverage the built-in stream hardware which will automatically perform an atomic increment
// on the register. This can save precious erisc cycles by offloading a lot of pointer manipulation.
// Additionally, these registers are accessible via eth_reg_write calls which can be used to write a value,
// inline the eth command (without requiring source L1)
template <uint32_t stream_id>
void increment_local_update_ptr_val(int32_t val) {
    NOC_STREAM_WRITE_REG_FIELD(stream_id, STREAM_REMOTE_DEST_BUF_SPACE_AVAILABLE_UPDATE_REG_INDEX, REMOTE_DEST_BUF_WORDS_FREE_INC, val);
}
void increment_local_update_ptr_val(uint8_t stream_id, int32_t val) {
    NOC_STREAM_WRITE_REG_FIELD(stream_id, STREAM_REMOTE_DEST_BUF_SPACE_AVAILABLE_UPDATE_REG_INDEX, REMOTE_DEST_BUF_WORDS_FREE_INC, val);
}

template <uint32_t stream_id>
void remote_update_ptr_val(int32_t val) {
    constexpr uint32_t addr = STREAM_REG_ADDR(stream_id, STREAM_REMOTE_DEST_BUF_SPACE_AVAILABLE_UPDATE_REG_INDEX);
    eth_write_remote_reg(addr, val << REMOTE_DEST_BUF_WORDS_FREE_INC);
}
void remote_update_ptr_val(uint32_t stream_id, int32_t val) {
    const uint32_t addr = STREAM_REG_ADDR(stream_id, STREAM_REMOTE_DEST_BUF_SPACE_AVAILABLE_UPDATE_REG_INDEX);
    eth_write_remote_reg(addr, val << REMOTE_DEST_BUF_WORDS_FREE_INC);
}

template <uint32_t stream_id>
void init_ptr_val(int32_t val) {
    NOC_STREAM_WRITE_REG(stream_id, STREAM_REMOTE_DEST_BUF_SIZE_REG_INDEX, val);
}

constexpr std::array<uint32_t, 2> to_sender_packets_acked_streams = {{
    to_sender_0_pkts_acked_id,
    to_sender_1_pkts_acked_id
}};

constexpr std::array<uint32_t, 2> to_sender_packets_completed_streams = {{
    to_sender_0_pkts_completed_id,
    to_sender_1_pkts_completed_id
}};

/*
 * Tracks receiver channel pointers (from sender side)
 */
template <uint8_t RECEIVER_NUM_BUFFERS>
struct OutboundReceiverChannelPointers {
    tt::fabric::ChannelBufferPointer<RECEIVER_NUM_BUFFERS> wrptr;
    tt::fabric::ChannelBufferPointer<RECEIVER_NUM_BUFFERS> ack_ptr;
    tt::fabric::ChannelBufferPointer<RECEIVER_NUM_BUFFERS> completion_ptr;

    bool has_space_for_packet() const {
        return completion_ptr.distance_behind(wrptr) < RECEIVER_NUM_BUFFERS;
    }

    bool has_unacknowledged_eth_packets() const {
        return ack_ptr.get_ptr() != wrptr.get_ptr();
    }

    bool has_incomplete_eth_packets() const {
        return completion_ptr.get_ptr() != wrptr.get_ptr();
    }

    bool has_unacknowledged_or_incomplete_eth_packets() const {
        return has_incomplete_eth_packets() || has_unacknowledged_eth_packets();
    }
};

/*
 * Tracks receiver channel pointers (from receiver side)
 */
template <uint8_t RECEIVER_NUM_BUFFERS>
struct ReceiverChannelPointers {
    tt::fabric::ChannelBufferPointer<RECEIVER_NUM_BUFFERS> wr_sent_ptr;
    tt::fabric::ChannelBufferPointer<RECEIVER_NUM_BUFFERS> wr_flush_ptr;
    tt::fabric::ChannelBufferPointer<RECEIVER_NUM_BUFFERS> ack_ptr;
    tt::fabric::ChannelBufferPointer<RECEIVER_NUM_BUFFERS> completion_ptr;
};

struct PacketHeaderRecorder {
    volatile tt::fabric::PacketHeader *buffer_ptr;
    size_t buffer_n_headers;
    size_t buffer_index;

    PacketHeaderRecorder(volatile tt::fabric::PacketHeader *buffer_ptr, size_t buffer_n_headers) : buffer_ptr(buffer_ptr), buffer_n_headers(buffer_n_headers), buffer_index(0) {}

    void record_packet_header(volatile tt::fabric::PacketHeader *packet_header_ptr) {
        uint32_t dest_l1_addr = (uint32_t)buffer_ptr + buffer_index * sizeof(tt::fabric::PacketHeader);
        noc_async_write(
            (uint32_t)packet_header_ptr,
            get_noc_addr(my_x[0], my_y[0], dest_l1_addr),
            sizeof(tt::fabric::PacketHeader),
            1 - noc_index // avoid the contention on main noc
        );
        buffer_index++;
        if (buffer_index == buffer_n_headers) {
            buffer_index = 0;
        }
    }
};

enum SenderState : uint8_t {
    SENDER_DONE = 0,

    // we are ready to tell the worker(s) that the buffer is available for writing into
    SENDER_SIGNALING_WORKER,

    // we are waiting for the payload to arrive in L1; we are checking local semaphore for worker
    // completion
    SENDER_WAITING_FOR_WORKER,

    // this state is enterred if the sender was able to send the payload but not the channel sync
    SENDER_SEND_CHANNEL_SYNC,

    // Sender channel is not connected to a worker and is waiting for a new connection
    SENDER_WAIT_WORKER_HANDSHAKE,

    // means we are waiting for ack from receiver that payload was received
    SENDER_WAITING_FOR_ETH,

};

enum ReceiverState : uint8_t {
    RECEIVER_DONE = 0,

    // Receiver is processing the packet, either writing it locally or forwarding to the next EDM
    // (toward next chip), or both
    RECEIVER_SENDING_PAYLOAD,

    // Enter this state after performing writes of the current packet as a sort of soft barrier
    // (for this channel only) so we can make progress on other channels while waiting for the
    // writes to flush
    RECEIVER_WAITING_FOR_WRITE_FLUSH,

    // means we are waitinf for a payload from sender
    RECEIVER_WAITING_FOR_ETH,
};


enum PacketLocalForwardType : uint8_t {
    PACKET_FORWARD_INVALID = 0x0,
    PACKET_FORWARD_LOCAL_ONLY = 0x1,
    PACKET_FORWARD_REMOTE_ONLY = 0x2,
    PACKET_FORWARD_LOCAL_AND_REMOTE = 0x3
};

static constexpr uint32_t SWITCH_INTERVAL =
#ifndef DEBUG_PRINT_ENABLED
get_compile_time_arg_val(0);
#else
0;
#endif

static constexpr size_t ETH_BYTES_TO_WORDS_SHIFT = 4;
static constexpr size_t NUM_SENDER_CHANNELS = 2;
static constexpr size_t num_workers_ctor = 1;
static constexpr size_t num_messages_to_move_ctor_value = 1;
// Doesn't REALLY matter but for consistency I picked the next available ID
static constexpr size_t receiver_channel_id = NUM_SENDER_CHANNELS;
static constexpr size_t worker_info_offset_past_connection_semaphore = 32;


/////////////////////////////////////////////
//   SENDER SIDE HELPERS
/////////////////////////////////////////////

template <uint8_t SENDER_NUM_BUFFERS, uint8_t RECEIVER_NUM_BUFFERS>
void send_channel_sync(
    tt::fabric::EthChannelBuffer<SENDER_NUM_BUFFERS> &sender_buffer_channel,
    tt::fabric::ChannelBufferPointer<SENDER_NUM_BUFFERS> &sender_wrptr,
    tt::fabric::EthChannelBuffer<RECEIVER_NUM_BUFFERS> &receiver_buffer_channel,
    tt::fabric::ChannelBufferPointer<RECEIVER_NUM_BUFFERS> &remote_receiver_wrptr
    ) {
    auto src_addr = sender_buffer_channel.get_bytes_sent_address(sender_wrptr.get_buffer_index());
    auto dest_addr = receiver_buffer_channel.get_bytes_sent_address(remote_receiver_wrptr.get_buffer_index());
    eth_send_bytes_over_channel_payload_only_unsafe(
        reinterpret_cast<size_t>(src_addr),
        reinterpret_cast<size_t>(dest_addr),
        sizeof(eth_channel_sync_t),
        sizeof(eth_channel_sync_t),
        sizeof(eth_channel_sync_t) >> ETH_BYTES_TO_WORDS_SHIFT);
}

template <uint8_t SENDER_NUM_BUFFERS, uint8_t RECEIVER_NUM_BUFFERS>
void send_next_data(
    tt::fabric::EthChannelBuffer<SENDER_NUM_BUFFERS> &sender_buffer_channel,
    tt::fabric::EdmChannelWorkerInterface<SENDER_NUM_BUFFERS> &sender_worker_interface,
    OutboundReceiverChannelPointers<RECEIVER_NUM_BUFFERS> &outbound_to_receiver_channel_pointers,
    tt::fabric::EthChannelBuffer<RECEIVER_NUM_BUFFERS> &receiver_buffer_channel,
    uint8_t sender_channel_index) {

    auto &remote_receiver_wrptr = outbound_to_receiver_channel_pointers.wrptr;
    auto &local_sender_wrptr = sender_worker_interface.local_wrptr;
    auto local_sender_wrptr_buffer_index = local_sender_wrptr.get_buffer_index();

    ASSERT(!eth_txq_is_busy());

    // TODO: TUNING - experiment with only conditionally breaking the transfer up into multiple packets if we are
    //       a certain threshold less than full packet
    //       we can precompute this value even on host and pass it in so we can get away with a single integer
    //       compare
    //       NOTE: if we always send full packet, then we don't need the second branch below dedicated for
    //             channel sync
    auto volatile *pkt_header =
        reinterpret_cast<volatile tt::fabric::PacketHeader *>(sender_buffer_channel.get_buffer_address(local_sender_wrptr_buffer_index));
    ASSERT(tt::fabric::is_valid(*const_cast<tt::fabric::PacketHeader *>(pkt_header)));
    size_t payload_size = 0;
    payload_size = pkt_header->get_payload_size_including_header();
    pkt_header->src_ch_id = sender_channel_index;

    auto src_addr = sender_buffer_channel.get_buffer_address(local_sender_wrptr_buffer_index);
    auto dest_addr = receiver_buffer_channel.get_buffer_address(remote_receiver_wrptr.get_buffer_index());
    eth_send_bytes_over_channel_payload_only_unsafe(
        src_addr,
        dest_addr,
        payload_size,
        payload_size,
        payload_size >> ETH_BYTES_TO_WORDS_SHIFT);


    // Note: We can only advance to the next buffer index if we have fully completed the send (both the payload and sync
    // messages)
    local_sender_wrptr.increment();
    // update the remote reg
    static constexpr uint32_t words_to_forward = 1;
    remote_update_ptr_val<to_receiver_pkts_sent_id>(words_to_forward);
    remote_receiver_wrptr.increment();
}



/////////////////////////////////////////////
//   RECEIVER SIDE HELPERS
/////////////////////////////////////////////

/*
 * Acting the receiver, we are looking at our receiver channel and acking the sender who sent us the latest packet.
 * Doesn't check to see if indeed a new message is available. It's assumed the caller has handled that separately.
 * MUST CHECK !is_eth_txq_busy() before calling
 */
template <size_t NUM_SENDER_CHANNELS, uint8_t SENDER_NUM_BUFFERS, uint8_t RECEIVER_NUM_BUFFERS>
void receiver_send_received_ack(
    std::array<tt::fabric::ChannelBufferPointer<SENDER_NUM_BUFFERS>, NUM_SENDER_CHANNELS> &remote_eth_sender_ackptrs,
    std::array<tt::fabric::EthChannelBuffer<SENDER_NUM_BUFFERS>, NUM_SENDER_CHANNELS> &remote_sender_channels,
    // currently the pointer is working multiple jobs (ack, completion, read) because we haven't implemented the
    // decoupling of those jobs yet to separate pointrers
    tt::fabric::ChannelBufferPointer<RECEIVER_NUM_BUFFERS> &receiver_channel_ptr,
    tt::fabric::EthChannelBuffer<RECEIVER_NUM_BUFFERS> &local_receiver_buffer_channel) {
    // Set the acknowledgement bits. We have a different location than the

    auto receiver_buffer_index = receiver_channel_ptr.get_buffer_index();
    auto volatile *pkt_header = reinterpret_cast<volatile tt::fabric::PacketHeader *>(local_receiver_buffer_channel.get_buffer_address(receiver_buffer_index));
    const auto src_id = pkt_header->src_ch_id;
    remote_update_ptr_val(to_sender_packets_acked_streams[src_id], 1);
}

// MUST CHECK !is_eth_txq_busy() before calling
template <size_t NUM_SENDER_CHANNELS, uint8_t SENDER_NUM_BUFFERS, uint8_t RECEIVER_NUM_BUFFERS>
FORCE_INLINE void receiver_send_completion_ack(
    std::array<tt::fabric::ChannelBufferPointer<SENDER_NUM_BUFFERS>, NUM_SENDER_CHANNELS> &remote_eth_sender_completion_ptrs,
    std::array<tt::fabric::EthChannelBuffer<SENDER_NUM_BUFFERS>, NUM_SENDER_CHANNELS> &remote_sender_channels,
    tt::fabric::ChannelBufferPointer<RECEIVER_NUM_BUFFERS> &receiver_channel_ptr,
    tt::fabric::EthChannelBuffer<RECEIVER_NUM_BUFFERS> &local_receiver_buffer_channel) {

    auto receiver_buffer_index = receiver_channel_ptr.get_buffer_index();

    auto volatile *pkt_header = reinterpret_cast<volatile tt::fabric::PacketHeader *>(local_receiver_buffer_channel.get_buffer_address(receiver_buffer_index));
    const auto src_id = pkt_header->src_ch_id;
    remote_update_ptr_val(to_sender_packets_completed_streams[src_id], 1);
    receiver_channel_ptr.increment();
    auto &remote_sender_completion_ptr = remote_eth_sender_completion_ptrs[src_id];
    remote_sender_completion_ptr.increment();
}


PacketLocalForwardType get_packet_local_forward_type(const volatile tt::fabric::PacketHeader &packet_header) {
    const bool local_chip_is_packet_destination = packet_must_be_consumed_locally(packet_header);
    const bool packet_needs_forwarding = packet_must_be_forwarded_to_next_chip(packet_header);
    PacketLocalForwardType forward_type =
        static_cast<PacketLocalForwardType>(packet_needs_forwarding << 1 | local_chip_is_packet_destination);
    return forward_type;
}

FORCE_INLINE bool can_forward_packet_completely(
    const volatile tt::fabric::PacketHeader *packet_header, tt::fabric::WorkerToFabricEdmSender &downstream_edm_interface) {
    auto forward_status = get_packet_local_forward_type(*packet_header);

    switch (forward_status) {
        case PACKET_FORWARD_INVALID: return false;
        case PACKET_FORWARD_LOCAL_ONLY: return true;

        case PACKET_FORWARD_REMOTE_ONLY:
        case PACKET_FORWARD_LOCAL_AND_REMOTE: return downstream_edm_interface.edm_has_space_for_packet();
        default: ASSERT(false); return false;
    };
}

// !!!WARNING!!! - MAKE SURE CONSUMER HAS SPACE BEFORE CALLING
void receiver_forward_packet(
    volatile tt::fabric::PacketHeader *packet_start, tt::fabric::WorkerToFabricEdmSender &downstream_edm_interface) {
    // Just cache the packet_header - we don't really expect (or care) if contents change during this function.
    volatile tt::fabric::PacketHeader const &packet_header = *packet_start;
    ASSERT(tt::fabric::is_valid(const_cast<tt::fabric::PacketHeader const &>(packet_header)));
    auto forward_status = get_packet_local_forward_type(packet_header);
    switch (forward_status) {
        case PACKET_FORWARD_LOCAL_ONLY: {
            execute_chip_unicast_to_local_chip(packet_start);
        } break;

        case PACKET_FORWARD_REMOTE_ONLY: {
            forward_payload_to_downstream_edm(packet_start, downstream_edm_interface);
        } break;

        case PACKET_FORWARD_LOCAL_AND_REMOTE: {
            ASSERT(packet_header.chip_send_type == tt::fabric::ChipSendType::CHIP_MULTICAST);
            // TODO: make local chip write non-blocking
            execute_chip_unicast_to_local_chip(packet_start);
            forward_payload_to_downstream_edm(packet_start, downstream_edm_interface);
        } break;

        case PACKET_FORWARD_INVALID:
        default: ASSERT(false);
    };
}

////////////////////////////////////
////////////////////////////////////
//  Main Control Loop
////////////////////////////////////
////////////////////////////////////
template <bool enable_packet_header_recording, bool enable_fabric_counters, uint8_t RECEIVER_NUM_BUFFERS, uint8_t SENDER_NUM_BUFFERS>
bool run_sender_channel_step(
    tt::fabric::EthChannelBuffer<SENDER_NUM_BUFFERS> &local_sender_channel,
    tt::fabric::EdmChannelWorkerInterface<SENDER_NUM_BUFFERS> &local_sender_channel_worker_interface,
    OutboundReceiverChannelPointers<RECEIVER_NUM_BUFFERS> &outbound_to_receiver_channel_pointers,
    tt::fabric::EthChannelBuffer<RECEIVER_NUM_BUFFERS> &remote_receiver_channel,
    volatile tt::fabric::EdmFabricSenderChannelCounters* sender_channel_counters,
    PacketHeaderRecorder &packet_header_recorder,
    bool &channel_connection_established,
    uint8_t sender_channel_index) {
    bool did_something = false;

    // If the receiver has space, and we have one or more packets unsent from producer, then send one
    // TODO: convert to loop to send multiple packets back to back (or support sending multiple packets in one shot)
    //       when moving to stream regs to manage rd/wr ptrs
    // TODO: update to be stream reg based. Initialize to space available and simply check for non-zero
    bool receiver_has_space_for_packet = outbound_to_receiver_channel_pointers.has_space_for_packet();
    if (receiver_has_space_for_packet && !eth_txq_is_busy()) {
        bool has_unsent_packet = local_sender_channel_worker_interface.has_unsent_payload();
        if (has_unsent_packet) {
            bool sender_backpressured_from_sender_side = !(local_sender_channel_worker_interface.local_rdptr.distance_behind(local_sender_channel_worker_interface.local_wrptr) < SENDER_NUM_BUFFERS);
            if (!sender_backpressured_from_sender_side) {
                did_something = true;
                auto packet_header = reinterpret_cast<tt::fabric::PacketHeader*>(local_sender_channel.get_buffer_address(local_sender_channel_worker_interface.local_wrptr.get_buffer_index()));
                if constexpr (enable_packet_header_recording) {
                    tt::fabric::validate(*packet_header);
                    packet_header_recorder.record_packet_header(packet_header);
                }
                print_pkt_header(packet_header);
                send_next_data(
                    local_sender_channel,
                    local_sender_channel_worker_interface,
                    outbound_to_receiver_channel_pointers,
                    remote_receiver_channel,
                    sender_channel_index);
            }
        }
    }

    // Process COMPLETIONs from receiver
    int32_t completions_since_last_check = get_ptr_val(to_sender_packets_completed_streams[sender_channel_index]);
    if (completions_since_last_check > 0) {
        auto& sender_rdptr = local_sender_channel_worker_interface.local_rdptr;
        outbound_to_receiver_channel_pointers.completion_ptr.increment_n(completions_since_last_check);
        sender_rdptr.increment_n(completions_since_last_check);
        increment_local_update_ptr_val(to_sender_packets_completed_streams[sender_channel_index], -completions_since_last_check);
    }

    // Process ACKs from receiver
    // ACKs are processed second to avoid any sort of races. If we process acks second,
    // we are guaranteed to see equal to or greater the number of acks than completions
    auto acks_since_last_check = get_ptr_val(to_sender_packets_acked_streams[sender_channel_index]);

    auto& sender_ackptr = local_sender_channel_worker_interface.local_ackptr;
    if (acks_since_last_check > 0) {
        sender_ackptr.increment_n(acks_since_last_check);
        if (channel_connection_established) {
            local_sender_channel_worker_interface.update_worker_copy_of_read_ptr();
        }
        increment_local_update_ptr_val(to_sender_packets_acked_streams[sender_channel_index], -acks_since_last_check);
    }
    did_something = did_something || (completions_since_last_check + acks_since_last_check) > 0;


    if (!channel_connection_established) {
        // Can get rid of one of these two checks if we duplicate the logic above here in the function
        // and depending on which of the two versions we are in (the connected version or disconnected version)
        // We also check if the interface has a teardown request in case worker
        // 1. opened connection
        // 2. sent of all packets (EDM sender channel was sufficiently empty)
        // 3. closed the connection
        //
        // In such a case like that, we still want to formally teardown the connection to keep things clean
        bool connect_requested = local_sender_channel_worker_interface.connection_is_live() ||
                                 local_sender_channel_worker_interface.has_worker_teardown_request();
        if (connect_requested) {
            if constexpr (enable_fabric_counters) {
                sender_channel_counters->add_connection();
            }
            did_something = true;
            channel_connection_established = true;
            local_sender_channel_worker_interface.update_worker_copy_of_read_ptr();
        }
    } else if (local_sender_channel_worker_interface.has_worker_teardown_request()) {
        did_something = true;
        channel_connection_established = false;
        local_sender_channel_worker_interface.teardown_connection(
            local_sender_channel_worker_interface.local_rdptr.get_ptr());
    }

    return did_something;
};

template <bool enable_packet_header_recording, bool enable_fabric_counters, size_t RECEIVER_NUM_BUFFERS, size_t SENDER_NUM_BUFFERS, size_t NUM_SENDER_CHANNELS>
void run_receiver_channel_step(
    tt::fabric::EthChannelBuffer<RECEIVER_NUM_BUFFERS> &local_receiver_channel,
    std::array<tt::fabric::EthChannelBuffer<SENDER_NUM_BUFFERS>, NUM_SENDER_CHANNELS> &remote_sender_channnels,
    tt::fabric::WorkerToFabricEdmSender &downstream_edm_interface,
    volatile tt::fabric::EdmFabricReceiverChannelCounters *receiver_channel_counters_ptr,
    std::array<tt::fabric::ChannelBufferPointer<SENDER_NUM_BUFFERS>, NUM_SENDER_CHANNELS> &remote_eth_sender_wrptrs,
    ReceiverChannelPointers<RECEIVER_NUM_BUFFERS> &receiver_channel_pointers,
    PacketHeaderRecorder &packet_header_recorder,
    ReceiverState *const receiver_state_out) {

    auto &ack_ptr = receiver_channel_pointers.ack_ptr;
    auto pkts_received_since_last_check = get_ptr_val<to_receiver_pkts_sent_id>();
    bool pkts_received = pkts_received_since_last_check > 0;
    bool can_send_over_eth = !eth_txq_is_busy();
    ASSERT(receiver_channel_pointers.completion_ptr.distance_behind(ack_ptr) < RECEIVER_NUM_BUFFERS);
    if (pkts_received && can_send_over_eth) {
        // currently only support processing one packet at a time, so we only decrement by 1
        increment_local_update_ptr_val<to_receiver_pkts_sent_id>(-1);
        receiver_send_received_ack(
            remote_eth_sender_wrptrs,
            remote_sender_channnels,
            ack_ptr,
            local_receiver_channel);
        ack_ptr.increment();
    }

    auto &wr_sent_ptr = receiver_channel_pointers.wr_sent_ptr;
    bool unwritten_packets = !wr_sent_ptr.is_caught_up_to(ack_ptr);
    if (unwritten_packets) {
        auto receiver_buffer_index = wr_sent_ptr.get_buffer_index();
        volatile auto packet_header = local_receiver_channel.get_packet_header(receiver_buffer_index);
        print_pkt_header(packet_header);
        bool can_send_to_all_local_chip_receivers =
            can_forward_packet_completely(packet_header, downstream_edm_interface);
        if (can_send_to_all_local_chip_receivers) {
            receiver_forward_packet(packet_header, downstream_edm_interface);
            wr_sent_ptr.increment();
        }
    }

    auto &wr_flush_ptr = receiver_channel_pointers.wr_flush_ptr;
    bool unflushed_writes = !wr_flush_ptr.is_caught_up_to(wr_sent_ptr);
    if (unflushed_writes) {
        bool writes_flushed = ncrisc_noc_nonposted_writes_sent(noc_index);
        if (writes_flushed) {
            auto receiver_buffer_index = wr_flush_ptr.get_buffer_index();
            local_receiver_channel.eth_clear_sender_channel_ack(receiver_buffer_index);
            wr_flush_ptr.increment();
        }
    }

    auto &completion_ptr = receiver_channel_pointers.completion_ptr;
    bool unsent_completions = !completion_ptr.is_caught_up_to(wr_flush_ptr);
    if (unsent_completions) {
        bool can_send_without_blocking = !eth_txq_is_busy();
        if (can_send_without_blocking) {
            // completion ptr incremented in callee
            receiver_send_completion_ack(
                remote_eth_sender_wrptrs,
                remote_sender_channnels,
                completion_ptr,
                local_receiver_channel);
        }
    }
};


/* Termination signal handling*/
FORCE_INLINE bool got_immediate_termination_signal(volatile tt::fabric::TerminationSignal *termination_signal_ptr) {
    return *termination_signal_ptr == tt::fabric::TerminationSignal::IMMEDIATELY_TERMINATE;
}
FORCE_INLINE bool got_graceful_termination_signal(volatile tt::fabric::TerminationSignal *termination_signal_ptr) {
    return *termination_signal_ptr == tt::fabric::TerminationSignal::GRACEFULLY_TERMINATE;
}
FORCE_INLINE bool got_termination_signal(volatile tt::fabric::TerminationSignal *termination_signal_ptr) {
    return got_immediate_termination_signal(termination_signal_ptr) ||
           got_graceful_termination_signal(termination_signal_ptr);
}

template <size_t RECEIVER_NUM_BUFFERS, size_t SENDER_NUM_BUFFERS, size_t NUM_SENDER_CHANNELS>
bool all_channels_drained(tt::fabric::EthChannelBuffer<RECEIVER_NUM_BUFFERS> &local_receiver_channel,
                          std::array<tt::fabric::EthChannelBuffer<SENDER_NUM_BUFFERS>, NUM_SENDER_CHANNELS> &local_sender_channels,
                          std::array<tt::fabric::EdmChannelWorkerInterface<SENDER_NUM_BUFFERS>, NUM_SENDER_CHANNELS> &local_sender_channel_worker_interfaces,
                          ReceiverChannelPointers<RECEIVER_NUM_BUFFERS> &receiver_channel_pointers) {

    bool eth_buffers_drained =
        local_sender_channel_worker_interfaces[0].all_eth_packets_completed() &&
        local_sender_channel_worker_interfaces[1].all_eth_packets_completed() &&
        !local_sender_channel_worker_interfaces[0].has_unsent_payload() &&
        !local_sender_channel_worker_interfaces[1].has_unsent_payload() &&
        receiver_channel_pointers.completion_ptr.is_caught_up_to(receiver_channel_pointers.ack_ptr) &&
        get_ptr_val<to_receiver_pkts_sent_id>() == 0 &&
        get_ptr_val<to_sender_0_pkts_acked_id>() == 0 &&
        get_ptr_val<to_sender_1_pkts_acked_id>() == 0 &&
        get_ptr_val<to_sender_0_pkts_completed_id>() == 0 &&
        get_ptr_val<to_sender_1_pkts_completed_id>() == 0;

    return eth_buffers_drained;
}

/*
 * Main control loop for fabric EDM. Run indefinitely until a termination signal is received
 *
 * Every loop iteration visit a sender channel and the receiver channel. Switch between sender
 * channels every iteration unless it is unsafe/undesirable to do so (e.g. for performance reasons).
 */
template <bool enable_packet_header_recording, bool enable_fabric_counters, size_t RECEIVER_NUM_BUFFERS, size_t SENDER_NUM_BUFFERS, size_t NUM_SENDER_CHANNELS>
void run_fabric_edm_main_loop(
    tt::fabric::EthChannelBuffer<RECEIVER_NUM_BUFFERS> &local_receiver_channel,
    std::array<tt::fabric::EthChannelBuffer<SENDER_NUM_BUFFERS>, NUM_SENDER_CHANNELS> &local_sender_channels,
    std::array<tt::fabric::EdmChannelWorkerInterface<SENDER_NUM_BUFFERS>, NUM_SENDER_CHANNELS> &local_sender_channel_worker_interfaces,
    tt::fabric::WorkerToFabricEdmSender &downstream_edm_noc_interface,
    std::array<tt::fabric::EthChannelBuffer<SENDER_NUM_BUFFERS>, NUM_SENDER_CHANNELS> &remote_sender_channels,
    tt::fabric::EthChannelBuffer<RECEIVER_NUM_BUFFERS> &remote_receiver_channel,
    volatile tt::fabric::TerminationSignal *termination_signal_ptr,
    volatile tt::fabric::EdmFabricReceiverChannelCounters *receiver_channel_counters_ptr,
    std::array<volatile tt::fabric::EdmFabricSenderChannelCounters *, NUM_SENDER_CHANNELS> sender_channel_counters_ptrs,
    PacketHeaderRecorder &receiver_channel_packet_recorder,
    std::array<PacketHeaderRecorder, NUM_SENDER_CHANNELS> &sender_channel_packet_recorders) {
    std::array<SenderState, NUM_SENDER_CHANNELS> sender_states = {
        SenderState::SENDER_WAIT_WORKER_HANDSHAKE, SenderState::SENDER_WAIT_WORKER_HANDSHAKE};
    ReceiverState receiver_state = ReceiverState::RECEIVER_WAITING_FOR_ETH;
    size_t sender_channel_index = 0;
    size_t did_nothing_count = 0;
    *termination_signal_ptr = tt::fabric::TerminationSignal::KEEP_RUNNING;

    // May want to promote to part of the handshake but for now we just initialize in this standalone way
    // TODO: flatten all of these arrays into a single object (one array lookup) OR
    //       (probably better) pack most of these into single words (e.g. we could hold a read, write, and ackptr in a single word)
    //       this way - especially if power of 2 wraps, we can handle both channels literally at once with math ops on single individual
    //       words (or half words)
    std::array<tt::fabric::ChannelBufferPointer<SENDER_NUM_BUFFERS>, NUM_SENDER_CHANNELS> remote_eth_sender_wrptrs {
        tt::fabric::ChannelBufferPointer<SENDER_NUM_BUFFERS>(),
        tt::fabric::ChannelBufferPointer<SENDER_NUM_BUFFERS>()};
    OutboundReceiverChannelPointers<RECEIVER_NUM_BUFFERS> outbound_to_receiver_channel_pointers;
    ReceiverChannelPointers<RECEIVER_NUM_BUFFERS> receiver_channel_pointers;
    std::array<bool, NUM_SENDER_CHANNELS> channel_connection_established = {false, false};

    while (!got_immediate_termination_signal(termination_signal_ptr)) {
        bool got_graceful_termination = got_graceful_termination_signal(termination_signal_ptr);
        if (got_graceful_termination) {
            DPRINT << "EDM Graceful termination\n";
            bool all_drained = all_channels_drained<RECEIVER_NUM_BUFFERS, SENDER_NUM_BUFFERS, NUM_SENDER_CHANNELS>(
                local_receiver_channel, local_sender_channels, local_sender_channel_worker_interfaces, receiver_channel_pointers);

            if (all_drained) {
                return;
            }
        }

        // Capture these to see if we made progress
        auto old_recv_state = receiver_state;

        // There are some cases, mainly for performance, where we don't want to switch between sender channels
        // so we interoduce this to provide finer grain control over when we disable the automatic switching
        bool did_something_sender = run_sender_channel_step<enable_packet_header_recording, enable_fabric_counters>(
            local_sender_channels[sender_channel_index],
            local_sender_channel_worker_interfaces[sender_channel_index],
            outbound_to_receiver_channel_pointers,
            remote_receiver_channel,
            sender_channel_counters_ptrs[sender_channel_index],
            sender_channel_packet_recorders[sender_channel_index],
            channel_connection_established[sender_channel_index],
            sender_channel_index);

        sender_channel_index = 1 - sender_channel_index;

        run_receiver_channel_step<enable_packet_header_recording, enable_fabric_counters, RECEIVER_NUM_BUFFERS, SENDER_NUM_BUFFERS, NUM_SENDER_CHANNELS>(
            local_receiver_channel, remote_sender_channels, downstream_edm_noc_interface, receiver_channel_counters_ptr,
            remote_eth_sender_wrptrs,
            receiver_channel_pointers,
            receiver_channel_packet_recorder, &receiver_state);

        bool did_something = did_something_sender || old_recv_state != receiver_state;

        if (did_something) {
            did_nothing_count = 0;
        } else {
            if (did_nothing_count++ > SWITCH_INTERVAL) {
                did_nothing_count = 0;
                run_routing();
            }
        }
    }
    DPRINT << "EDM Terminating\n";
}

void kernel_main() {
    //
    // COMMON CT ARGS (not specific to sender or receiver)
    //
    static constexpr bool is_handshake_sender = get_compile_time_arg_val(1) != 0;
    static constexpr size_t handshake_addr = get_compile_time_arg_val(2);
    *reinterpret_cast<volatile uint32_t*>(handshake_addr) = 0;
    auto eth_transaction_ack_word_addr = handshake_addr + sizeof(eth_channel_sync_t);

    // Initialize stream register state for credit management across the Ethernet link.
    // We make sure to do this before we handshake to guarantee that the registers are
    // initialized before the other side has any possibility of modifying them.
    init_ptr_val<to_receiver_pkts_sent_id>(0);
    init_ptr_val<to_sender_0_pkts_acked_id>(0);
    init_ptr_val<to_sender_1_pkts_acked_id>(0);
    init_ptr_val<to_sender_0_pkts_completed_id>(0);
    init_ptr_val<to_sender_1_pkts_completed_id>(0);

    static constexpr size_t DEFAULT_HANDSHAKE_CONTEXT_SWITCH_TIMEOUT = 0;
    if constexpr (is_handshake_sender) {
        erisc::datamover::handshake::sender_side_start(handshake_addr, DEFAULT_HANDSHAKE_CONTEXT_SWITCH_TIMEOUT);
    } else {
        erisc::datamover::handshake::receiver_side_start(handshake_addr);
    }

    // the size of one of the buffers within a sender channel
    // For example if `channel_buffer_size` = 4k, with `SENDER_NUM_BUFFERS` = 2
    // then the total amount of buffering for that
    static constexpr size_t channel_buffer_size = get_compile_time_arg_val(3);

    static constexpr size_t SENDER_NUM_BUFFERS = get_compile_time_arg_val(4);
    static constexpr size_t RECEIVER_NUM_BUFFERS = get_compile_time_arg_val(5);
    static constexpr size_t local_sender_0_channel_address = get_compile_time_arg_val(6);
    static constexpr size_t local_sender_channel_0_connection_info_addr = get_compile_time_arg_val(7);
    static constexpr size_t local_sender_1_channel_address = get_compile_time_arg_val(8);
    static constexpr size_t local_sender_channel_1_connection_info_addr = get_compile_time_arg_val(9);
    static constexpr size_t local_receiver_channel_buffer_address = get_compile_time_arg_val(10);
    static constexpr size_t remote_receiver_channel_buffer_address = get_compile_time_arg_val(11);
    static constexpr size_t remote_sender_0_channel_address = get_compile_time_arg_val(12);
    static constexpr size_t remote_sender_1_channel_address = get_compile_time_arg_val(13);

    DPRINT << "SENDER_NUM_BUFFERS: " << (uint32_t)SENDER_NUM_BUFFERS << "\n";
    DPRINT << "RECEIVER_NUM_BUFFERS: " << (uint32_t)RECEIVER_NUM_BUFFERS << "\n";
    DPRINT << "local_sender_0_channel_address: " << (uint32_t)local_sender_0_channel_address << "\n";
    DPRINT << "local_sender_channel_0_connection_info_addr: " << (uint32_t)local_sender_channel_0_connection_info_addr << "\n";
    DPRINT << "local_sender_1_channel_address: " << (uint32_t)local_sender_1_channel_address << "\n";
    DPRINT << "local_sender_channel_1_connection_info_addr: " << (uint32_t)local_sender_channel_1_connection_info_addr << "\n";
    DPRINT << "local_receiver_channel_buffer_address: " << (uint32_t)local_receiver_channel_buffer_address << "\n";
    DPRINT << "remote_receiver_channel_buffer_address: " << (uint32_t)remote_receiver_channel_buffer_address << "\n";
    DPRINT << "remote_sender_0_channel_address: " << (uint32_t)remote_sender_0_channel_address << "\n";
    DPRINT << "remote_sender_1_channel_address: " << (uint32_t)remote_sender_1_channel_address << "\n";

    // TODO: CONVERT TO SEMAPHORE
    volatile auto termination_signal_ptr =
        reinterpret_cast<volatile tt::fabric::TerminationSignal *>(get_compile_time_arg_val(14));
    // In persistent mode, we must rely on static addresses for our local semaphores that are locally
    // initialized, rather than metal device APIs. This way different subdevice programs can reliably
    // resolve the semaphore addresses on the EDM core
    static constexpr bool persistent_mode = get_compile_time_arg_val(15) != 0;

    // Per-channel counters
    static constexpr bool enable_fabric_counters = get_compile_time_arg_val(16) != 0;
    static constexpr size_t receiver_channel_counters_address = get_compile_time_arg_val(17);
    static constexpr size_t sender_channel_0_counters_address = get_compile_time_arg_val(18);
    static constexpr size_t sender_channel_1_counters_address = get_compile_time_arg_val(19);

    static constexpr bool enable_packet_header_recording = get_compile_time_arg_val(20) != 0;
    static constexpr size_t receiver_completed_packet_header_cb_address = get_compile_time_arg_val(21);
    static constexpr size_t receiver_completed_packet_header_cb_size_headers = get_compile_time_arg_val(22);
    static constexpr size_t sender_0_completed_packet_header_cb_address = get_compile_time_arg_val(23);
    static constexpr size_t sender_0_completed_packet_header_cb_size_headers = get_compile_time_arg_val(24);
    static constexpr size_t sender_1_completed_packet_header_cb_address = get_compile_time_arg_val(25);
    static constexpr size_t sender_1_completed_packet_header_cb_size_headers = get_compile_time_arg_val(26);

    std::array<PacketHeaderRecorder, NUM_SENDER_CHANNELS> sender_channel_packet_recorders{
        PacketHeaderRecorder(
            reinterpret_cast<volatile tt::fabric::PacketHeader *>(sender_0_completed_packet_header_cb_address),
            sender_0_completed_packet_header_cb_size_headers),
        PacketHeaderRecorder(
            reinterpret_cast<volatile tt::fabric::PacketHeader *>(sender_1_completed_packet_header_cb_address),
            sender_1_completed_packet_header_cb_size_headers)
    };
    PacketHeaderRecorder receiver_channel_packet_recorder(
        reinterpret_cast<volatile tt::fabric::PacketHeader *>(receiver_completed_packet_header_cb_address),
        receiver_completed_packet_header_cb_size_headers);

    static_assert(SENDER_NUM_BUFFERS > 0, "compile time argument [1]: SENDER_NUM_BUFFERS must be > 0");
    static_assert(RECEIVER_NUM_BUFFERS > 0, "compile time argument [2]: RECEIVER_NUM_BUFFERS must be > 0");

    volatile tt::fabric::EdmFabricReceiverChannelCounters *receiver_channel_counters_ptr = nullptr;
    volatile tt::fabric::EdmFabricSenderChannelCounters *sender_channel_0_counters_ptr = nullptr;
    volatile tt::fabric::EdmFabricSenderChannelCounters *sender_channel_1_counters_ptr = nullptr;

    if constexpr (enable_fabric_counters) {
        new (const_cast<tt::fabric::EdmFabricReceiverChannelCounters*>(receiver_channel_counters_ptr)) tt::fabric::EdmFabricReceiverChannelCounters();
        new (const_cast<tt::fabric::EdmFabricSenderChannelCounters*>(sender_channel_0_counters_ptr)) tt::fabric::EdmFabricSenderChannelCounters();
        new (const_cast<tt::fabric::EdmFabricSenderChannelCounters*>(sender_channel_1_counters_ptr)) tt::fabric::EdmFabricSenderChannelCounters();
    }

    size_t arg_idx = 0;
    ///////////////////////
    // Common runtime args:
    ///////////////////////

    const size_t local_sender_channel_0_connection_semaphore_addr =
        persistent_mode ? get_arg_val<uint32_t>(arg_idx++) :
        get_semaphore<ProgrammableCoreType::ACTIVE_ETH>(get_arg_val<uint32_t>(arg_idx++));
    const size_t local_sender_channel_1_connection_semaphore_addr =
        get_semaphore<ProgrammableCoreType::ACTIVE_ETH>(get_arg_val<uint32_t>(arg_idx++));

    // unused - can later remove
    const size_t local_sender_channel_0_connection_buffer_index_addr =
        persistent_mode ? get_arg_val<uint32_t>(arg_idx++) :
        get_semaphore<ProgrammableCoreType::ACTIVE_ETH>(get_arg_val<uint32_t>(arg_idx++));

    const size_t local_sender_channel_1_connection_buffer_index_id = get_arg_val<uint32_t>(arg_idx++);


    // downstream EDM semaphore location
    const bool has_downstream_edm_buffer_connection = get_arg_val<uint32_t>(arg_idx++) != 0;
    const auto downstream_edm_buffer_base_address = get_arg_val<uint32_t>(arg_idx++);
    const auto downstream_edm_noc_x = get_arg_val<uint32_t>(arg_idx++);
    const auto downstream_edm_noc_y = get_arg_val<uint32_t>(arg_idx++);

    // remote address for flow control
    const auto downstream_edm_semaphore_id = get_arg_val<uint32_t>(arg_idx++);  // TODO: Convert to semaphore ID
    const auto downstream_edm_worker_registration_id = get_arg_val<uint32_t>(arg_idx++);
    const auto downstream_edm_worker_location_info_address = get_arg_val<uint32_t>(arg_idx++);
    const auto downstream_noc_interface_buffer_index_local_addr = get_arg_val<uint32_t>(arg_idx++);

    // Receiver channels local semaphore for managing flow control with the downstream EDM.
    // The downstream EDM should be sending semaphore updates to this address any time it can
    // accept a new message
    const auto edm_forwarding_semaphore_address =
        get_semaphore<ProgrammableCoreType::ACTIVE_ETH>(get_arg_val<uint32_t>(arg_idx++));
    const auto edm_teardown_semaphore_address =
        get_semaphore<ProgrammableCoreType::ACTIVE_ETH>(get_arg_val<uint32_t>(arg_idx++));

    ////////////////////////
    // Sender runtime args
    ////////////////////////
    auto sender0_worker_semaphore_ptr = reinterpret_cast<volatile uint32_t *>(
        persistent_mode ? get_arg_val<uint32_t>(arg_idx++) :
        get_semaphore<ProgrammableCoreType::ACTIVE_ETH>(get_arg_val<uint32_t>(arg_idx++)));
    auto sender1_worker_semaphore_ptr = reinterpret_cast<volatile uint32_t *>(
        get_semaphore<ProgrammableCoreType::ACTIVE_ETH>(get_arg_val<uint32_t>(arg_idx++)));

    if constexpr (persistent_mode) {
        // initialize the statically allocated "semaphores"
        *reinterpret_cast<volatile uint32_t*>(local_sender_channel_0_connection_semaphore_addr) = 0;
        *reinterpret_cast<volatile uint32_t*>(local_sender_channel_0_connection_buffer_index_addr) = 0;
        *sender0_worker_semaphore_ptr = 0;
    }
    //////////////////////////////
    //////////////////////////////
    //        Object Setup
    //////////////////////////////
    //////////////////////////////

    auto const &local_sender_buffer_addresses =
        std::array<size_t, NUM_SENDER_CHANNELS>{local_sender_0_channel_address, local_sender_1_channel_address};
    auto const &remote_sender_buffer_addresses =
        std::array<size_t, NUM_SENDER_CHANNELS>{remote_sender_0_channel_address, remote_sender_1_channel_address};
    std::array<tt::fabric::EthChannelBuffer<SENDER_NUM_BUFFERS>, NUM_SENDER_CHANNELS> remote_sender_channels;
    std::array<tt::fabric::EthChannelBuffer<SENDER_NUM_BUFFERS>, NUM_SENDER_CHANNELS> local_sender_channels;
    std::array<tt::fabric::EdmChannelWorkerInterface<SENDER_NUM_BUFFERS>, NUM_SENDER_CHANNELS> local_sender_channel_worker_interfaces;
    std::array<size_t, NUM_SENDER_CHANNELS> local_sender_flow_control_semaphores = {
        reinterpret_cast<size_t>(sender0_worker_semaphore_ptr), reinterpret_cast<size_t>(sender1_worker_semaphore_ptr)};
    std::array<size_t, NUM_SENDER_CHANNELS> local_sender_connection_live_semaphore_addresses = {
        local_sender_channel_0_connection_semaphore_addr, local_sender_channel_1_connection_semaphore_addr};
    std::array<size_t, NUM_SENDER_CHANNELS> local_sender_connection_info_addresses = {
        local_sender_channel_0_connection_info_addr, local_sender_channel_1_connection_info_addr};
    for (size_t i = 0; i < NUM_SENDER_CHANNELS; i++) {
        auto connection_worker_info_ptr = reinterpret_cast<volatile tt::fabric::EDMChannelWorkerLocationInfo *>(
            local_sender_connection_info_addresses[i]);
        connection_worker_info_ptr->edm_rdptr = 0;
    }
    auto downstream_edm_noc_interface =
        has_downstream_edm_buffer_connection
            ? tt::fabric::WorkerToFabricEdmSender(
                 //persistent_mode -> hardcode to false because for EDM -> EDM
                 // connections we must always use semaphore lookup
                  false,
                  downstream_edm_noc_x,
                  downstream_edm_noc_y,
                  downstream_edm_buffer_base_address,
                  SENDER_NUM_BUFFERS,
                  downstream_edm_semaphore_id,
                  downstream_edm_worker_registration_id,
                  downstream_edm_worker_location_info_address,
                  channel_buffer_size,
                  local_sender_channel_1_connection_buffer_index_id,
                  reinterpret_cast<volatile uint32_t *const>(edm_forwarding_semaphore_address),
                  reinterpret_cast<volatile uint32_t *const>(edm_teardown_semaphore_address),
                  downstream_noc_interface_buffer_index_local_addr)
            : tt::fabric::WorkerToFabricEdmSender();

    auto local_receiver_channel = tt::fabric::EthChannelBuffer<RECEIVER_NUM_BUFFERS>(
        local_receiver_channel_buffer_address,
        channel_buffer_size,
        tt::fabric::header_size_bytes,
        eth_transaction_ack_word_addr,  // Assume for receiver channel, this address points to a chunk of memory that
                                        // can fit 2 eth_channel_syncs cfor ack
        receiver_channel_id);
    auto remote_receiver_channel = tt::fabric::EthChannelBuffer<RECEIVER_NUM_BUFFERS>(
        remote_receiver_channel_buffer_address,
        channel_buffer_size,
        tt::fabric::header_size_bytes,
        eth_transaction_ack_word_addr,  // Assume for receiver channel, this address points to a chunk of memory that
                                        // can fit 2 eth_channel_syncs cfor ack
        receiver_channel_id);

    uint32_t args_offset = 0;

    for (uint8_t i = 0; i < NUM_SENDER_CHANNELS; i++) {
        new (&local_sender_channels[i]) tt::fabric::EthChannelBuffer<SENDER_NUM_BUFFERS>(
            local_sender_buffer_addresses[i],
            channel_buffer_size,
            tt::fabric::header_size_bytes,
            0,  // For sender channels there is no eth_transaction_ack_word_addr because they don't send acks
            i);
        new (&remote_sender_channels[i]) tt::fabric::EthChannelBuffer<SENDER_NUM_BUFFERS>(
            remote_sender_buffer_addresses[i],
            channel_buffer_size,
            tt::fabric::header_size_bytes,
            0,  // For sender channels there is no eth_transaction_ack_word_addr because they don't send acks
            i);

        auto connection_live_semaphore_ptr =
            reinterpret_cast<volatile tt_l1_ptr uint32_t *const>(local_sender_connection_live_semaphore_addresses[i]);
        auto connection_worker_info_ptr = reinterpret_cast<volatile tt::fabric::EDMChannelWorkerLocationInfo *>(
            local_sender_connection_info_addresses[i]);
        connection_worker_info_ptr->edm_rdptr = 0;
        new (&local_sender_channel_worker_interfaces[i]) tt::fabric::EdmChannelWorkerInterface<SENDER_NUM_BUFFERS>(
            connection_worker_info_ptr,
            reinterpret_cast<volatile tt_l1_ptr uint32_t *const>(
                local_sender_flow_control_semaphores[i]),
            reinterpret_cast<volatile tt_l1_ptr uint32_t *const>(connection_live_semaphore_ptr));
    }


    if (has_downstream_edm_buffer_connection) {
        downstream_edm_noc_interface.open();
        *downstream_edm_noc_interface.from_remote_buffer_slot_rdptr_ptr = 0;
        ASSERT(*downstream_edm_noc_interface.from_remote_buffer_slot_rdptr_ptr == 0);
    }

    if constexpr (is_handshake_sender) {
        erisc::datamover::handshake::sender_side_finish(handshake_addr, DEFAULT_HANDSHAKE_CONTEXT_SWITCH_TIMEOUT);
    } else {
        erisc::datamover::handshake::receiver_side_finish(handshake_addr, DEFAULT_HANDSHAKE_CONTEXT_SWITCH_TIMEOUT);
    }

    //////////////////////////////
    //////////////////////////////
    //        MAIN LOOP
    //////////////////////////////
    //////////////////////////////
    run_fabric_edm_main_loop<enable_packet_header_recording, enable_fabric_counters, RECEIVER_NUM_BUFFERS, SENDER_NUM_BUFFERS, NUM_SENDER_CHANNELS>(
        local_receiver_channel,
        local_sender_channels,
        local_sender_channel_worker_interfaces,
        downstream_edm_noc_interface,
        remote_sender_channels,
        remote_receiver_channel,
        termination_signal_ptr,
        receiver_channel_counters_ptr,
        {sender_channel_0_counters_ptr, sender_channel_1_counters_ptr},
        receiver_channel_packet_recorder,
        sender_channel_packet_recorders);


    if constexpr (persistent_mode) {
        // we force these values to a non-zero value so that if we run the fabric back to back,
        // and we can reliably probe from host that this kernel has initialized properly.
        *reinterpret_cast<volatile uint32_t*>(local_sender_channel_0_connection_semaphore_addr) = 99;
        *reinterpret_cast<volatile uint32_t*>(local_sender_channel_0_connection_buffer_index_addr) = 99;
        *sender0_worker_semaphore_ptr = 99;
    }

    DPRINT << "EDM DONE\n";
    WAYPOINT("DONE");
}
