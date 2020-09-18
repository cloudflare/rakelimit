#pragma once

#include <ip.h>
#include <stddef.h>

struct packet_element {
	__u16 source_port;
	__u16 destination_port;
	struct in6_addr source_address;
	struct in6_addr destination_address;
};

_Static_assert(sizeof(struct packet_element) == sizeof(__u16) * 2 + sizeof(struct in6_addr) * 2, "wrong packet_element size");
