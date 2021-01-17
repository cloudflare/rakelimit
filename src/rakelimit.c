#include <in.h>
#include <ip.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common.h"
#include "countmin.h"
#include "fasthash.h"

static volatile const __u32 LIMIT;

enum address_gen {
	ADDRESS_IP       = 0, // /32 or /128
	ADDRESS_NET      = 1, // /24 or /48
	ADDRESS_WILDCARD = 2, // /0
};

enum address_specifier {
	SOURCE,
	DEST,
};

enum port_gen {
	PORT_SPECIFIED = 0,
	PORT_WILDCARD  = 1,
};

struct gen {
	enum address_gen source;
	enum port_gen source_port;
	enum address_gen dest;
	enum port_gen dest_port;
	bool evaluate;
};

static const struct gen generalisations[] = {
	/*level 0*/
	{ADDRESS_IP, PORT_SPECIFIED, ADDRESS_IP, PORT_SPECIFIED, true},

	/* level 1 */
	{ADDRESS_NET, PORT_SPECIFIED, ADDRESS_IP, PORT_SPECIFIED, false},
	{ADDRESS_IP, PORT_WILDCARD, ADDRESS_IP, PORT_SPECIFIED, false},
	{ADDRESS_IP, PORT_SPECIFIED, ADDRESS_IP, PORT_WILDCARD, true},

	/* level 2 */
	/* *.*.*.*:i --> w.x.y.z:j */
	{ADDRESS_WILDCARD, PORT_SPECIFIED, ADDRESS_IP, PORT_SPECIFIED, false},
	/* a.b.c.*:* --> w.x.y.z:j */
	{ADDRESS_NET, PORT_WILDCARD, ADDRESS_IP, PORT_SPECIFIED, false},
	/* a.b.c.*:i --> w.x.y.z:* */
	{ADDRESS_NET, PORT_SPECIFIED, ADDRESS_IP, PORT_WILDCARD, false},
	/* a.b.c.d:* --> w.x.y.z:* */
	{ADDRESS_IP, PORT_WILDCARD, ADDRESS_IP, PORT_WILDCARD, true},

	/* level 3 */
	/* *.*.*.*:* --> w.x.y.z:j */
	{ADDRESS_WILDCARD, PORT_WILDCARD, ADDRESS_IP, PORT_SPECIFIED, false},
	/* *.*.*.*:i --> w.x.y.z:* */
	{ADDRESS_WILDCARD, PORT_SPECIFIED, ADDRESS_IP, PORT_WILDCARD, false},
	/* A.B.C.*:* --> w.x.y.z:* */
	{ADDRESS_NET, PORT_WILDCARD, ADDRESS_IP, PORT_WILDCARD, true},

	/* level 4 */
	{ADDRESS_WILDCARD, PORT_WILDCARD, ADDRESS_IP, PORT_WILDCARD, true},
};

struct packet {
	__u16 source_port;
	__u16 destination_port;
	union {
		struct {
			struct in_addr source_address;
			struct in_addr destination_address;
		} ipv4;
		struct {
			struct in6_addr source_address;
			struct in6_addr destination_address;
		} ipv6;
	};
};

_Static_assert(sizeof(struct packet) == sizeof(__u16) * 2 + sizeof(struct in6_addr) * 2, "wrong packet size");

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
	.max_entries = ARRAY_SIZE(generalisations),
};

static int FORCE_INLINE gen_level(const struct gen *gen)
{
	// The enum values are chosen so that they add up to the correct level.
	return gen->source + gen->source_port + gen->dest + gen->dest_port;
}

static __u32 FORCE_INLINE add_to_node(__u32 node_idx, __u64 ts, void *element, __u64 len)
{
	struct countmin *node = bpf_map_lookup_elem(&countmin, &node_idx);
	if (node == NULL) {
		return -1;
	}
	return cm_add_and_query(node, ts, element, len);
}

static FORCE_INLINE void log_level_drop(__u32 level)
{
	__u64 *count = bpf_map_lookup_elem(&stats, &level);
	if (count == NULL) {
		return;
	}
	(*count)++;
}

static FORCE_INLINE __u64 transport_offset_ipv4(struct __sk_buff *skb)
{
	__u8 version_ihl = load_byte(skb, offsetof(struct iphdr, version_ihl));
	return (version_ihl & 0xf) * sizeof(__u32);
}

static FORCE_INLINE __u64 transport_offset_ipv6(struct __sk_buff *skb)
{
	// TODO: Check nexthdr to make sure it's UDP.
	return sizeof(struct ip6_hdr);
}

static FORCE_INLINE void fill_ipv4(struct in_addr *ip, struct __sk_buff *skb, enum address_gen type, enum address_specifier spec)
{
	__u64 off = spec == SOURCE ? offsetof(struct iphdr, saddr) : offsetof(struct iphdr, daddr);

	if (type == ADDRESS_WILDCARD) {
		ip->s_addr = 0;
		return;
	}

	ip->s_addr = load_word(skb, BPF_NET_OFF + off);

	switch (type) {
	case ADDRESS_NET:
		ip->s_addr &= 0xffffff00;
		break;

	case ADDRESS_WILDCARD: // Already handled above.
	case ADDRESS_IP:       // Nothing to do.
		break;
	}
}

static FORCE_INLINE void fill_ipv6(struct in6_addr *ip, struct __sk_buff *skb, enum address_gen type, enum address_specifier spec)
{
	__u64 off = spec == SOURCE ? offsetof(struct ip6_hdr, ip6_src) : offsetof(struct ip6_hdr, ip6_dst);

	if (type == ADDRESS_WILDCARD) {
		*ip = (struct in6_addr){0};
		return;
	}

	// TODO: This can return an error.
	bpf_skb_load_bytes(skb, off, ip, sizeof(*ip));

	// 16: 0    1    2    3    4    5    6    7
	// 32: 0         1         2         3
	// /48 ffff ffff ffff 0000 0000 0000 0000 0000
	// /64 ffff ffff ffff ffff 0000 0000 0000 0000
	switch (type) {
	case ADDRESS_NET:
		ip->s6_addr16[3] = 0;
		ip->s6_addr32[2] = 0;
		ip->s6_addr32[3] = 0;
		break;

	case ADDRESS_WILDCARD: // Already handled above.
	case ADDRESS_IP:       // Nothing to do.
		break;
	}
}

static FORCE_INLINE int drop_or_accept(__u32 level, fpoint limit, __u32 max_rate, __u32 rand)
{
	if (div_by_int(to_fixed_point(limit, 0), max_rate) < to_fixed_point(0, rand)) {
		log_level_drop(level);
		return SKB_REJECT;
	}
	return SKB_PASS;
}

static FORCE_INLINE int process_packet(struct __sk_buff *skb, __u16 proto, __u64 ts, __u32 rand, __u64 *rate_exceeded_level)
{
	struct packet pkt = {0};
	__u32 max_rate    = 0;

	if (LIMIT == 0) {
		return SKB_PASS;
	}

	__u64 troff;
	switch (proto) {
	case ETH_P_IP:
		troff = transport_offset_ipv4(skb);
		break;

	case ETH_P_IPV6:
		troff = transport_offset_ipv6(skb);
		break;

	default:
		return SKB_REJECT;
	}

#pragma clang loop unroll(full)
	for (int i = 0; i < ARRAY_SIZE(generalisations); i++) {
		const struct gen *gen = &generalisations[i];
		__u32 rate;

		pkt.source_port      = (gen->source_port == PORT_WILDCARD) ? 0 : load_half(skb, troff);
		pkt.destination_port = (gen->dest_port == PORT_WILDCARD) ? 0 : load_half(skb, troff + 2);

		switch (proto) {
		case ETH_P_IP:
			fill_ipv4(&pkt.ipv4.source_address, skb, gen->source, SOURCE);
			fill_ipv4(&pkt.ipv4.destination_address, skb, gen->dest, DEST);
			rate = add_to_node(i, ts, &pkt, offsetofend(struct packet, ipv4));
			break;

		case ETH_P_IPV6:
			fill_ipv6(&pkt.ipv6.source_address, skb, gen->source, SOURCE);
			fill_ipv6(&pkt.ipv6.destination_address, skb, gen->dest, DEST);
			rate = add_to_node(i, ts, &pkt, offsetofend(struct packet, ipv6));
			break;
		}

		if (rate > max_rate) {
			max_rate = rate;
		}

		if (gen->evaluate) {
			if (max_rate > LIMIT) {
				if (rate_exceeded_level != NULL) {
					*rate_exceeded_level = gen_level(gen);
				}
				return drop_or_accept(gen_level(gen), LIMIT, max_rate, rand);
			}

			max_rate = 0;
		}
	}

	return SKB_PASS;
}

SEC("socket/ipv4")
int filter_ipv4(struct __sk_buff *skb)
{
	return process_packet(skb, ETH_P_IP, bpf_ktime_get_ns(), bpf_get_prandom_u32(), NULL);
}

SEC("socket/ipv6")
int filter_ipv6(struct __sk_buff *skb)
{
	return process_packet(skb, ETH_P_IPV6, bpf_ktime_get_ns(), bpf_get_prandom_u32(), NULL);
}

// a map used for testing
struct bpf_map_def SEC("maps") test_single_result = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u64),
	.max_entries = 3,
};

static FORCE_INLINE int test_filter(struct __sk_buff *skb, __u16 proto)
{
	__u64 *ts, *randp, *rate_exceeded_level;
	__u32 rand;

	ts = bpf_map_lookup_elem(&test_single_result, &(__u32){0});
	if (ts == NULL) {
		return SKB_PASS;
	}

	randp = bpf_map_lookup_elem(&test_single_result, &(__u32){1});
	if (randp == NULL) {
		return SKB_PASS;
	}

	if (*randp > 0xffffffff) {
		rand = bpf_get_prandom_u32();
	} else {
		rand = *randp;
	}

	rate_exceeded_level = bpf_map_lookup_elem(&test_single_result, &(__u32){2});
	if (rate_exceeded_level == NULL) {
		return SKB_PASS;
	}

	// Always reset the level to some weird value that isn't zero.
	*rate_exceeded_level = -1;

	return process_packet(skb, proto, *ts, rand, rate_exceeded_level);
}

SEC("socket/test_ipv4")
int test_ipv4(struct __sk_buff *skb)
{
	return test_filter(skb, ETH_P_IP);
}

SEC("socket/test_ipv6")
int test_ipv6(struct __sk_buff *skb)
{
	return test_filter(skb, ETH_P_IPV6);
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
	if (to_fixed_point(27, 0) != *fp) {
		char msg[] = "[E] fixed points are not equal\n";
		bpf_trace_printk(msg, sizeof(msg));
		return SKB_REJECT;
	}
	// then replace it
	*fp = to_fixed_point(19, 0);
	bpf_map_update_elem(&test_single_result, &i, fp, 0);
	return SKB_PASS;
}

// test_ewma takes a previous rate from index 0 (as a u32) and an old and
// new timestamp from index 1-2 (as u64) and estimates the current rate.
// The result is written to the previous rate.
SEC("socket/test2")
int test_ewma(struct __sk_buff *skb)
{
	__u64 *old_rate = bpf_map_lookup_elem(&test_single_result, &(__u32){0});
	if (old_rate == NULL) {
		return SKB_REJECT;
	}

	__u64 *old_ts = bpf_map_lookup_elem(&test_single_result, &(__u32){1});
	if (old_ts == NULL) {
		return SKB_REJECT;
	}

	__u64 *now = bpf_map_lookup_elem(&test_single_result, &(__u32){2});
	if (now == NULL) {
		return SKB_REJECT;
	}

	*old_rate = estimate_rate(*old_rate, *old_ts, *now);
	return SKB_PASS;
}

char __license[] SEC("license") = "Dual BSD/GPL";
