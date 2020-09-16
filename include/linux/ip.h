#pragma once
#include "types.h"

// from linux/ip.h

//TODO: replace with musl header
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