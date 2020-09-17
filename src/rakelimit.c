#include <linux/bpf.h>
#include <linux/ip.h>
#include <stddef.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common.h"
#include "countmin.h"
#include "fasthash.h"
#include "packet_element.h"

#define NODES 12

enum address_cidr {
	ADDRESS_IP       = 0, // /32 or /64
	ADDRESS_NET      = 1, // /24 or /48
	ADDRESS_WILDCARD = 2, // /0
};

enum address_specifier {
	SOURCE,
	DEST,
};

enum port_cidr {
	PORT_SPECIFIED = 0,
	PORT_WILDCARD  = 1,
};

// collect number of packet drops per level
struct bpf_map_def SEC("maps") stats = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u64),
	.max_entries = 5, // 5 levels
};


struct bpf_map_def SEC("maps") countmin = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct countmin),
	.max_entries = NODES,
};

static fpoint FORCE_INLINE add_to_node(__u64 ts, int node_idx, struct packet_element *element)
{
	fpoint min = -1;
	__u32 target_idx;
	struct countmin *node = bpf_map_lookup_elem(&countmin, &node_idx);
	if (node == NULL) {
		return -1;
	}
	return add_to_cm(node, ts, element);
}


static FORCE_INLINE void log_level_drop(__u32 level)
{
	__u64 *count = bpf_map_lookup_elem(&stats, &level);
	if (count == NULL) {
		return;
	}
	(*count)++;
}

static volatile const fpoint limit = 0;

static FORCE_INLINE void fill_ip(__u8 ip[16], struct __sk_buff *skb, enum address_cidr type, enum address_specifier spec)
{
	__u64 off = 0;
	int len   = 0;
	//TODO: fix for IPv6
	if (spec == SOURCE) {
		off = offsetof(struct iphdr, saddr);
	} else {
		off = offsetof(struct iphdr, daddr);
	}

#pragma clang loop unroll(full)
	for (int i = 0; i < 16; i++) {
		ip[i] = 0; // reset everything
	}

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		if (type == ADDRESS_NET || type == ADDRESS_IP) {
			ip[12] = load_byte(skb, BPF_NET_OFF + off);
			ip[13] = load_byte(skb, BPF_NET_OFF + off + 1);
			ip[14] = load_byte(skb, BPF_NET_OFF + off + 2);
		}
		if (type == ADDRESS_IP) {
			ip[15] = load_byte(skb, BPF_NET_OFF + off + 3);
		}
		ip[10] = 0xff;
		ip[11] = 0xff;
	}

	// ipv6
	else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		if (type == ADDRESS_NET) {
			len = 6; // 48
		} else if (type == ADDRESS_IP) {
			if (spec == SOURCE) {
				len = 8; // 64
			} else if (spec == DEST) {
				len = 16; // 128
			}
		}

#pragma clang loop unroll(full)
		for (int i = 0; i < len; i++) {
			ip[i] = load_byte(skb, BPF_NET_OFF + off + i);
		}
	}
	return;
}

static FORCE_INLINE void fill_port(__u16 *port, struct __sk_buff *skb, enum address_specifier addr, enum port_cidr type)
{
	if (type == PORT_WILDCARD) {
		*port = 0;
		return;
	}
	if (addr == DEST) {
		// assuming TCP or UDP, offsets 2-3 of L4 are dport
		*port = (load_byte(skb, 2) << 8) | load_byte(skb, 3);
	} else if (addr == SOURCE) {
		*port = (load_byte(skb, 0) << 8) | load_byte(skb, 1);
	}
	return;
}

static FORCE_INLINE void generalise(struct packet_element *element, struct __sk_buff *skb, enum address_cidr sourceAddressPrefix, enum port_cidr generaliseSourcePort, enum address_cidr destinationAddressPrefix, enum port_cidr generaliseDestinationPort)
{
	fill_ip(element->source_address, skb, sourceAddressPrefix, SOURCE);
	fill_ip(element->destination_address, skb, destinationAddressPrefix, DEST);
	fill_port(&element->source_port, skb, SOURCE, generaliseSourcePort);
	fill_port(&element->destination_port, skb, DEST, generaliseDestinationPort);
}

static FORCE_INLINE int drop_or_accept(__u32 level, fpoint limit, fpoint max_rate)
{
	fpoint rand = bpf_get_prandom_u32();
	if (div_by_int(limit, max_rate) < rand) {
		log_level_drop(level);
		return SKB_REJECT;
	}
	return SKB_PASS;
}

static FORCE_INLINE fpoint estimate_max_rate(fpoint max_rate, __u64 ts, __u32 node_index, struct packet_element *element)
{
	fpoint rate = add_to_node(ts, node_index, element);
	if (rate > max_rate) {
		return rate;
	}
	return max_rate;
}

static FORCE_INLINE int process_packet(struct __sk_buff *skb, __u64 ts)
{
	struct packet_element element = {0};
	fpoint max_rate               = 0;

	// get rate limit
	__u32 i             = 0;
	if (limit == 0) {
		return SKB_PASS;
	}

	/*level 0*/
	generalise(&element, skb, ADDRESS_IP, PORT_SPECIFIED, ADDRESS_IP, PORT_SPECIFIED);
	max_rate = estimate_max_rate(max_rate, ts, 0, &element);

	if (max_rate > limit) {
		return drop_or_accept(0, limit, max_rate);
	}

	/* level 1 */
	generalise(&element, skb, ADDRESS_NET, PORT_SPECIFIED, ADDRESS_IP, PORT_SPECIFIED);
	max_rate = estimate_max_rate(max_rate, ts, 1, &element);

	generalise(&element, skb, ADDRESS_IP, PORT_WILDCARD, ADDRESS_IP, PORT_SPECIFIED);
	max_rate = estimate_max_rate(max_rate, ts, 2, &element);

	generalise(&element, skb, ADDRESS_IP, PORT_SPECIFIED, ADDRESS_IP, PORT_WILDCARD);
	max_rate = estimate_max_rate(max_rate, ts, 3, &element);

	if (max_rate > limit) {	
		return drop_or_accept(1, limit, max_rate);
	}

	/* level 2 */
	/* *.*.*.*:i --> w.x.y.z:j */
	generalise(&element, skb, ADDRESS_WILDCARD, PORT_SPECIFIED, ADDRESS_IP, PORT_SPECIFIED);
	max_rate = estimate_max_rate(max_rate, ts, 4, &element);

	/* a.b.c.*:* --> w.x.y.z:j */
	generalise(&element, skb, ADDRESS_NET, PORT_WILDCARD, ADDRESS_IP, PORT_SPECIFIED);
	max_rate = estimate_max_rate(max_rate, ts, 5, &element);

	/* a.b.c.*:i --> w.x.y.z:* */
	generalise(&element, skb, ADDRESS_NET, PORT_SPECIFIED, ADDRESS_IP, PORT_WILDCARD);
	max_rate = estimate_max_rate(max_rate, ts, 6, &element);

	/* a.b.c.d:* --> w.x.y.z:* */
	generalise(&element, skb, ADDRESS_IP, PORT_WILDCARD, ADDRESS_IP, PORT_WILDCARD);
	max_rate = estimate_max_rate(max_rate, ts, 7, &element);

	if (max_rate > limit) {
		return drop_or_accept(2, limit, max_rate);
	}

	/* level 3 */
	/* *.*.*.*:* --> w.x.y.z:j */
	generalise(&element, skb, ADDRESS_IP, PORT_WILDCARD, ADDRESS_IP, PORT_SPECIFIED);
	max_rate = estimate_max_rate(max_rate, ts, 8, &element);

	/* *.*.*.*:i --> w.x.y.z:* */
	generalise(&element, skb, ADDRESS_IP, PORT_SPECIFIED, ADDRESS_IP, PORT_WILDCARD);
	max_rate = estimate_max_rate(max_rate, ts, 9, &element);

	/* A.B.C.*:* --> w.x.y.z:* */
	generalise(&element, skb, ADDRESS_NET, PORT_WILDCARD, ADDRESS_IP, PORT_WILDCARD);
	max_rate = estimate_max_rate(max_rate, ts, 10, &element);

	if (max_rate > limit) {
		return drop_or_accept(3, limit, max_rate);
	}

	/* level 4 */
	generalise(&element, skb, ADDRESS_WILDCARD, PORT_WILDCARD, ADDRESS_IP, PORT_WILDCARD);
	max_rate = estimate_max_rate(max_rate, ts, 11, &element);
	if (max_rate > limit) {
		return drop_or_accept(4, limit, max_rate);
	}
	return SKB_PASS;
}

// prod_anchor is the production entrypoint.
// it determines the current time and then calls on
// process_packet
SEC("socket/prod")
int prod_anchor(struct __sk_buff *skb)
{
	__u64 ts = bpf_ktime_get_ns();
	return process_packet(skb, ts);
}

// a map used for testing
struct bpf_map_def SEC("maps") test_single_result = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u64),
	.max_entries = 2,
};

// test_anchor_fn reads a timestamp from index 0
// and then continues with the normal execution using
// process packet
SEC("socket/test")
int test_anchor(struct __sk_buff *skb)
{
	__u64 *ts;
	__u32 i = 0;

	ts = bpf_map_lookup_elem(&test_single_result, &i);
	if (ts == NULL) {
		return SKB_PASS;
	}
	return process_packet(skb, *ts);
}

// test_fp_cmp takes the element with the index 0 out of the test_single_result map, and
// compares if it is equal to some randomly chosen integer converted to a fixed-point (27 in this case).
// Then we do the same thing the other way around and put a converted 19 into the map to ensure the userspace
// implementation does its job as well
SEC("socket/test1")
int test_fp_cmp(struct __sk_buff *skb)
{
	int i     = 0;
	__u64 *fp = bpf_map_lookup_elem(&test_single_result, &i);
	if (fp == NULL) {
		char msg[] = "[E] element 0 in map 'test_single_result' not found\n";
		bpf_trace_printk(msg, sizeof(msg));
		return SKB_REJECT;
	}
	// first check the value from userside
	if (to_fixed_point(27) != *fp) {
		char msg[] = "[E] fixed points are not equal\n";
		bpf_trace_printk(msg, sizeof(msg));
		return SKB_REJECT;
	}
	// then replace it
	*fp = to_fixed_point(19);
	bpf_map_update_elem(&test_single_result, &i, fp, 0);
	return SKB_PASS;
}

// test_ewma takes a previous rate from index 0 (as a fixed point)
// and a duration from index 1 (as an integer), estimates the current rate
// based on both and writes the result as a fixed point at index 1
SEC("socket/test2")
int test_ewma(struct __sk_buff *skb)
{
	int i        = 0;
	__u64 *value = bpf_map_lookup_elem(&test_single_result, &i);
	if (value == NULL) {
		return SKB_REJECT;
	}
	i          = 1;
	__u64 *dur = bpf_map_lookup_elem(&test_single_result, &i);
	if (dur == NULL) {
		return SKB_REJECT;
	}
	*value = estimate_avg_rate(*value, *dur);
	return SKB_PASS;
}

char __license[] SEC("license") = "Dual BSD/GPL";
