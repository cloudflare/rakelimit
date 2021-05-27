#include <in.h>
#include <ip.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <mindef.h>
#include <stdbool.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common.h"
#include "countmin.h"
#include "fasthash.h"

#define FH_SEED (0x2d31e867)
#define L3_SEED (0x6ad611c3)

#define PARAMETER(type, name) \
	({ \
		type __tmp; \
		_Static_assert(sizeof(__tmp) <= sizeof(__u64), name " exceeds 64 bits"); \
		asm("%0 = " name " ll" : "=r"(__tmp)); \
		__tmp; \
	})

enum address_gen {
	ADDRESS_IP       = 0, // /32 or /128
	ADDRESS_NET      = 1, // /24 or /48
	ADDRESS_WILDCARD = 2, // /0
};

enum port_gen {
	PORT_SPECIFIED = 0,
	PORT_WILDCARD  = 1,
};

struct gen {
	int level;
	enum address_gen source;
	enum port_gen source_port;
	enum address_gen dest;
	enum port_gen dest_port;
	bool evaluate;
};

struct address_hash {
	__u64 vals[ADDRESS_WILDCARD];
};

struct hash {
	struct address_hash src;
	struct address_hash dst;
	__u64 src_port;
	__u64 dst_port;
};

static const struct gen generalisations[] = {
	/*level 0*/
	{0, ADDRESS_IP, PORT_SPECIFIED, ADDRESS_IP, PORT_SPECIFIED, true},

	/* level 1 */
	{1, ADDRESS_NET, PORT_SPECIFIED, ADDRESS_IP, PORT_SPECIFIED, false},
	{1, ADDRESS_IP, PORT_WILDCARD, ADDRESS_IP, PORT_SPECIFIED, false},
	{1, ADDRESS_IP, PORT_SPECIFIED, ADDRESS_IP, PORT_WILDCARD, true},

	/* level 2 */
	/* *.*.*.*:i --> w.x.y.z:j */
	{2, ADDRESS_WILDCARD, PORT_SPECIFIED, ADDRESS_IP, PORT_SPECIFIED, false},
	/* a.b.c.*:* --> w.x.y.z:j */
	{2, ADDRESS_NET, PORT_WILDCARD, ADDRESS_IP, PORT_SPECIFIED, false},
	/* a.b.c.*:i --> w.x.y.z:* */
	{2, ADDRESS_NET, PORT_SPECIFIED, ADDRESS_IP, PORT_WILDCARD, false},
	/* a.b.c.d:* --> w.x.y.z:* */
	{2, ADDRESS_IP, PORT_WILDCARD, ADDRESS_IP, PORT_WILDCARD, true},

	/* level 3 */
	/* *.*.*.*:* --> w.x.y.z:j */
	{3, ADDRESS_WILDCARD, PORT_WILDCARD, ADDRESS_IP, PORT_SPECIFIED, false},
	/* *.*.*.*:i --> w.x.y.z:* */
	{3, ADDRESS_WILDCARD, PORT_SPECIFIED, ADDRESS_IP, PORT_WILDCARD, false},
	/* A.B.C.*:* --> w.x.y.z:* */
	{3, ADDRESS_NET, PORT_WILDCARD, ADDRESS_IP, PORT_WILDCARD, true},

	/* level 4 */
	{4, ADDRESS_WILDCARD, PORT_WILDCARD, ADDRESS_IP, PORT_WILDCARD, true},
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
	.max_entries = ARRAY_SIZE(generalisations),
};

static FORCE_INLINE void ipv6_hash(const struct in6_addr *ip, struct address_hash *a, struct address_hash *b)
{
	a->vals[ADDRESS_IP]  = fasthash64(ip, sizeof(*ip), FH_SEED);
	b->vals[ADDRESS_IP]  = hashlittle(ip, sizeof(*ip), L3_SEED);
	a->vals[ADDRESS_NET] = fasthash64(ip, 48 / 8, FH_SEED);
	b->vals[ADDRESS_NET] = hashlittle(ip, 48 / 8, L3_SEED);
}

static FORCE_INLINE void ipv4_hash(struct in_addr ip, struct address_hash *a, struct address_hash *b)
{
	a->vals[ADDRESS_IP] = fasthash64(&ip, sizeof(ip), FH_SEED);
	b->vals[ADDRESS_IP] = hashlittle(&ip, sizeof(ip), L3_SEED);
	ip.s_addr &= 0xffffff00;
	a->vals[ADDRESS_NET] = fasthash64(&ip, sizeof(ip), FH_SEED);
	b->vals[ADDRESS_NET] = hashlittle(&ip, sizeof(ip), L3_SEED);
}

static FORCE_INLINE __u64 hash_mix(__u64 a, __u64 b)
{
	// Adapted from https://stackoverflow.com/a/27952689. The constant below
	// is derived from the golden ratio.
	a ^= b + 0x9e3779b97f4a7c15 + (a << 6) + (a >> 2);
	return a;
}

static FORCE_INLINE __u32 gen_hash(const struct gen *gen, const struct hash *ph)
{
	__u64 tmp = 0;

	if (gen->source != ADDRESS_WILDCARD) {
		tmp = hash_mix(tmp, ph->src.vals[gen->source]);
	}

	if (gen->dest != ADDRESS_WILDCARD) {
		tmp = hash_mix(tmp, ph->dst.vals[gen->dest]);
	}

	if (gen->source_port != PORT_WILDCARD) {
		tmp = hash_mix(tmp, ph->src_port);
	}

	if (gen->dest_port != PORT_WILDCARD) {
		tmp = hash_mix(tmp, ph->dst_port);
	}

	// Adapted from fasthash32
	return tmp - (tmp >> 32);
}

static __u32 FORCE_INLINE add_to_node(__u32 node_idx, __u64 ts, const struct cm_hash *h)
{
	struct countmin *node = bpf_map_lookup_elem(&countmin, &node_idx);
	if (node == NULL) {
		return -1;
	}
	return cm_add_and_query(node, ts, h);
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

static FORCE_INLINE int load_ipv6(struct in6_addr *ip, struct __sk_buff *skb, __u64 off)
{
	return bpf_skb_load_bytes(skb, off, ip, sizeof(*ip));
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
	__u32 limit = PARAMETER(__u32, "LIMIT");
	struct hash ph[HASHFN_N];
	struct in6_addr ipv6;
	struct in_addr ipv4;
	__u32 max_rate = 0;

	if (limit == 0) {
		return SKB_PASS;
	}

	__u64 troff;
	switch (proto) {
	case ETH_P_IP:
		troff       = transport_offset_ipv4(skb);
		ipv4.s_addr = load_word(skb, BPF_NET_OFF + offsetof(struct iphdr, saddr));
		ipv4_hash(ipv4, &ph[0].src, &ph[1].src);
		ipv4.s_addr = load_word(skb, BPF_NET_OFF + offsetof(struct iphdr, daddr));
		ipv4_hash(ipv4, &ph[0].dst, &ph[1].dst);
		break;

	case ETH_P_IPV6:
		troff = transport_offset_ipv6(skb);
		if (load_ipv6(&ipv6, skb, offsetof(struct ip6_hdr, ip6_src))) {
			return SKB_REJECT;
		}
		ipv6_hash(&ipv6, &ph[0].src, &ph[1].src);
		if (load_ipv6(&ipv6, skb, offsetof(struct ip6_hdr, ip6_dst))) {
			return SKB_REJECT;
		}
		ipv6_hash(&ipv6, &ph[0].dst, &ph[1].dst);
		break;

	default:
		return SKB_REJECT;
	}

	__u16 src_port = load_half(skb, troff);
	ph[0].src_port = fasthash64(&src_port, sizeof(src_port), FH_SEED);
	ph[1].src_port = hashlittle(&src_port, sizeof(src_port), L3_SEED);
	__u16 dst_port = load_half(skb, troff + 2);
	ph[0].dst_port = fasthash64(&dst_port, sizeof(dst_port), FH_SEED);
	ph[1].dst_port = hashlittle(&dst_port, sizeof(dst_port), L3_SEED);

#pragma clang loop unroll(full)
	for (int i = 0; i < ARRAY_SIZE(generalisations); i++) {
		const struct gen *gen = &generalisations[i];
		const int level       = gen->level;

		// Force clang to inline level on the stack rather than loading it from
		// .rodata later on.
		asm volatile("" : : "r"(level) : "memory");

		struct cm_hash h = {{
			gen_hash(gen, &ph[0]),
			gen_hash(gen, &ph[1]),
		}};

		__u32 rate = add_to_node(i, ts, &h);

		if (rate > max_rate) {
			max_rate = rate;
		}

		if (gen->evaluate) {
			if (max_rate > limit) {
				if (rate_exceeded_level != NULL) {
					*rate_exceeded_level = level;
				}
				return drop_or_accept(level, limit, max_rate, rand);
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
		return __LINE__;
	}
	// first check the value from userside
	if (to_fixed_point(27, 0) != *fp) {
		return __LINE__;
	}
	// then replace it
	*fp = to_fixed_point(19, 0);
	bpf_map_update_elem(&test_single_result, &i, fp, 0);
	return 0;
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
