#ifndef __ENCAP_HELPERS_H
#define __ENCAP_HELPERS_H

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <string.h>

#include "bpf.h"
#include "bpf_debug.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

#include "balancer_consts.h"
#include "csum_helpers.h"

__attribute__((__always_inline__)) static inline void
create_v4_hdr(struct iphdr *iph, __u8 tos, __u32 saddr, __u32 daddr,
              __u16 pkt_bytes, __u8 proto) {
  __u64 csum = 0;
  // saddr = 3232293428;
  iph->version = 4;
  iph->ihl = 5;
  iph->frag_off = 0;
  iph->protocol = proto;
  iph->check = 0;
#ifdef COPY_INNER_PACKET_TOS
  iph->tos = tos;
#else
  iph->tos = DEFAULT_TOS;
#endif
  iph->tot_len = bpf_htons(pkt_bytes + sizeof(struct iphdr));
  iph->daddr = daddr;
  iph->saddr = saddr;
  // iph->saddr = bpf_htonl(saddr);
  iph->ttl = DEFAULT_TTL;
  ipv4_csum_inline(iph, &csum);
  iph->check = csum;
  debugf("create_v4_hdr saddr:%pI4 daddr:%pI4", &saddr, &daddr);
}

__attribute__((__always_inline__)) static inline void
create_v6_hdr(struct ipv6hdr *ip6h, __u8 tc, __u32 *saddr, __u32 *daddr,
              __u16 payload_len, __u8 proto) {
  ip6h->version = 6;
  memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
#ifdef COPY_INNER_PACKET_TOS
  ip6h->priority = (tc & 0xF0) >> 4;
  ip6h->flow_lbl[0] = (tc & 0x0F) << 4;
#else
  ip6h->priority = DEFAULT_TOS;
#endif
  ip6h->nexthdr = proto;
  ip6h->payload_len = bpf_htons(payload_len);
  ip6h->hop_limit = DEFAULT_TTL;
  memcpy(ip6h->saddr.s6_addr32, saddr, 16);
  memcpy(ip6h->daddr.s6_addr32, daddr, 16);
}

__attribute__((__always_inline__)) static inline void
create_udp_hdr(struct udphdr *udph, __u16 sport, __u16 dport, __u16 len,
               __u16 csum) {
  udph->source = sport;
  udph->dest = bpf_htons(dport);
  udph->len = bpf_htons(len);
  udph->check = csum;
}

#endif // of __ENCAP_HELPERS_H
