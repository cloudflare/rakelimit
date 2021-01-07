#pragma once

#include <linux/types.h>

// musl license: https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT

// from musl: include/netinet/in.h
struct in_addr {
	__u32 s_addr;
};

struct in6_addr {
	union {
		__u8 s6_addr[16];
		__u16 s6_addr16[8];
		__u32 s6_addr32[4];
	};
};