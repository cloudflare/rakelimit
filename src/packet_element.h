#pragma once

#define IP_BUFFER_LENGTH 16
#include <stddef.h>

struct packet_element {
	__u16 source_port;
	__u16 destination_port;
	__u8 source_address[IP_BUFFER_LENGTH];
	__u8 destination_address[IP_BUFFER_LENGTH];
};

_Static_assert(sizeof(struct packet_element) == IP_BUFFER_LENGTH + IP_BUFFER_LENGTH + 4, "wrong packet_element size");