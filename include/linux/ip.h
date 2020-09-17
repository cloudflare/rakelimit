#pragma once
#include "types.h"

// musl license: https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT

// from musl: include/netinet/ip.h
struct iphdr {
	unsigned int ihl:4;
	unsigned int version:4;
	__u8 tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
};

// from musl: include/netinet/in6.h
struct in6_addr {
	union {
		__u8  __s6_addr[16];
		__u16 __s6_addr16[8];
		__u32 __s6_addr32[4];
	} __in6_union;
};

// from musl: include/netinet/ip6.h
struct ip6_hdr {
	union {
		struct ip6_hdrctl {
			__u32 ip6_un1_flow;
			__u16 ip6_un1_plen;
			__u8  ip6_un1_nxt;
			__u8  ip6_un1_hlim;
		} ip6_un1;
		__u8 ip6_un2_vfc;
	} ip6_ctlun;
	struct in6_addr ip6_src;
	struct in6_addr ip6_dst;
};