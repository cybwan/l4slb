#ifndef __HEALTHCHECKING_CONSTS_H
#define __HEALTHCHECKING_CONSTS_H

#define CTRL_MAP_SIZE 4
// position of ifindex of main interface inside hc ctrl array
#define HC_MAIN_INTF_POSITION 3

#define REDIRECT_EGRESS 0
#define DEFAULT_TTL 64

// Specify max packet size to avoid packets exceed mss (after encapsulation)
// when set to 0, the healthchecker_kern would not perform skb length check,
// relying on GSO to segment packets exceeding MSS on transmit path
#ifndef HC_MAX_PACKET_SIZE
#define HC_MAX_PACKET_SIZE 0
#endif

// position in stats map where we are storing generic counters.
#define GENERIC_STATS_INDEX 0

// code to indicate that packet should be futher processed by pipeline
#define HC_FURTHER_PROCESSING -2

// size of stats map.
#define STATS_SIZE 1

#define NO_FLAGS 0

#define V6DADDR (1 << 0)

#define HC_SRC_MAC_POS 0
#define HC_DST_MAC_POS 1

#endif // of __HEALTHCHECKING_CONSTS_H
