#ifndef __HEALTHCHECKING_STRUCTS_H
#define __HEALTHCHECKING_STRUCTS_H

struct hc_real_definition {
  union {
    __be32 daddr;
    __be32 v6daddr[4];
  };
  __u8 flags;
};

// struct to record packet level for counters for relevant events
struct hc_stats {
  __u64 pckts_processed;
  __u64 pckts_dropped;
  __u64 pckts_skipped;
  __u64 pckts_too_big;
};

// hc_key's definition
struct hc_key {
  union {
    __be32 addr;
    __be32 addrv6[4];
  };
  __u16 port;
  __u8 proto;
};

// struct to store mac address
struct hc_mac {
  __u8 mac[6];
};

#endif // of __HEALTHCHECKING_STRUCTS_H
