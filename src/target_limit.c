/*
 * Rate limit datagrams to bind-to-star socket by maintainig a token
 * bucket for each (target IP, target port) tuples.
 *
 * Dual BSD/GPL license.
 */
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "bpf_helpers.h"
#include "bpf_typedefs.h"

#include "siphash.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define FORCE_INLINE inline __attribute__((__always_inline__))

struct key_t {
	uint8_t ip[16];
	uint16_t port;
};

struct limit_t {
	uint64_t last_timestamp;
	uint64_t credit;
};

// define some maps to store limits per group
// TARGET
#define TARGET_SIZE 512
struct bpf_map_def target_limit SEC("maps") = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(struct limit_t),
	.max_entries = TARGET_SIZE,
};

// SOURCE
#define SOURCE_SIZE 512
struct bpf_map_def source_limit SEC("maps") = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(struct limit_t),
	.max_entries = SOURCE_SIZE,
};


// SOURCENET
#define SOURCENET_SIZE 512
struct bpf_map_def sourcenet_limit SEC("maps") = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(struct limit_t),
	.max_entries = SOURCENET_SIZE,
};

// SOURCEPORT
#define SOURCEPORT_SIZE 2048
struct bpf_map_def sourceport_limit SEC("maps") = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(struct limit_t),
	.max_entries = SOURCEPORT_SIZE,
};

enum StatParam {
	PARAM_TARGET_COST,
	PARAM_TARGET_CREDIT_MAX,

	PARAM_SOURCE_COST,
	PARAM_SOURCE_CREDIT_MAX,

	PARAM_SOURCENET_COST,
	PARAM_SOURCENET_CREDIT_MAX,

	PARAM_SOURCEPORT_COST,
	PARAM_SOURCEPORT_CREDIT_MAX,

	/* Total number of analyzed packets */
	STAT_TOTAL,
	/* Packets dropped due to rate limit per target (IP, port) */
	STAT_DROP_TARGET,
	/* Packets dropped due to rate limit per source IP */
	STAT_DROP_SOURCE,
	/* Packets dropped due to rate limit per source network (/24 or /48) */
	STAT_DROP_SOURCENET,
	/* Packets dropped due to rate limit per source port */
	STAT_DROP_SOURCEPORT,
	/* Packets accepted, due to some error, not smartness. Should be zero.
	 */
	STAT_ERROR,
	STAT_MAX,
};


struct bpf_map_def stats SEC("maps") = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(uint64_t),
	.max_entries = STAT_MAX,
};

enum { SRC_IP = 0,
       DST_IP_PORT = 1,
       SRC_NET = 2,
       SRC_PORT = 3,
};

#define HTONS(n)                                                               \
	(((((unsigned short)(n)&0xFF)) << 8) |                                 \
	 (((unsigned short)(n)&0xFF00) >> 8))

static inline void incr_stat(enum StatParam no)
{
	uint64_t *value = bpf_map_lookup_elem(&stats, &no);
	if (value) {
		__sync_fetch_and_add(value, 1);
	}
}

static inline uint64_t param_get(enum StatParam no)
{
	uint64_t *value = bpf_map_lookup_elem(&stats, &no);
	if (value) {
		return *value;
	}
	return 0;
}

static inline void fill_ip(uint8_t ip[16], struct __sk_buff *skb, int type)
{
	uint64_t off = 0;
	int len;
	if (skb->protocol == HTONS(ETH_P_IP) && type == DST_IP_PORT) {
		off = __builtin_offsetof(struct iphdr, daddr);
		len = 4;
	} else if (skb->protocol == HTONS(ETH_P_IP) && type == SRC_IP) {
		off = __builtin_offsetof(struct iphdr, saddr);
		len = 4;
	} else if (skb->protocol == HTONS(ETH_P_IP) && type == SRC_NET) {
		off = __builtin_offsetof(struct iphdr, saddr);
		len = 3; // /24
	} else if (skb->protocol == HTONS(ETH_P_IPV6) && type == DST_IP_PORT) {
		off = __builtin_offsetof(struct ipv6hdr, daddr);
		len = 16;
	} else if (skb->protocol == HTONS(ETH_P_IPV6) && type == SRC_IP) {
		off = __builtin_offsetof(struct ipv6hdr, saddr);
		len = 8; // /64
	} else if (skb->protocol == HTONS(ETH_P_IPV6) && type == SRC_NET) {
		off = __builtin_offsetof(struct ipv6hdr, saddr);
		len = 6; // /48
	} else {
		return;
	}

	if (skb->protocol == HTONS(ETH_P_IP)) {
		ip[10] = 0xff;
		ip[11] = 0xff;
		int i;
#pragma clang loop unroll(full)
		for (i = 0; i < len; i++) {
			ip[12 + i] = load_byte(skb, BPF_NET_OFF + off + i);
		}
	} else if (skb->protocol == HTONS(ETH_P_IPV6)) {
		int i;
#pragma clang loop unroll(full)
		for (i = 0; i < len; i++) {
			ip[i] = load_byte(skb, BPF_NET_OFF + off + i);
		}
	}
	return;
}

static inline void fill_port(uint16_t *port, struct __sk_buff *skb, int type)
{
	if (type == DST_IP_PORT) {
		// assuming TCP or UDP, offsets 2-3 of L4 are dport
		*port = (load_byte(skb, 2) << 8) | load_byte(skb, 3);
	} else if (type == SRC_PORT) {
		// offsets 0-1 of L4 are sport
		*port = (load_byte(skb, 0) << 8) | load_byte(skb, 1);
	}
	return;
}

static inline uint64_t count_hash(struct __sk_buff *skb, int type)
{
	struct key_t k = {{0}, 0};
	fill_port(&k.port, skb, type);
	fill_ip(k.ip, skb, type);
	return siphash24(&k, sizeof(k));
}

/* Accept - allow any number of bytes */
#define SKB_PASS -1
/* Drop, cut packet to zero bytes */
#define SKB_REJECT 0

enum CreditVerdict {
	CREDIT_ERROR = -1, /* Error checking or deducting credit */
	CREDIT_OK,    /* Cost deducted successfully from available credit */
	CREDIT_EMPTY, /* Not enough credit available to cover the cost */
};

static inline int tokenbucket_bump(void *map, uint64_t now_ns, uint32_t shkey,
				   uint64_t cost, uint64_t credit_max)
{
	struct limit_t *value_old =
		(struct limit_t *)bpf_map_lookup_elem(map, &shkey);
	struct limit_t value = {0};
	int verdict = CREDIT_OK;

	// if this hasn't been used yet, just update the variables 
	if (!value_old ||
	    (value_old->last_timestamp == 0 && value_old->credit == 0)) {
		value.last_timestamp = now_ns;
		value.credit = credit_max;

		/* Not present. Insert it to the map. */
	} else {
		// if value available

		/* Copy over. Hoping for atomic. */
		value = *value_old;

		// bump the credits with the time that passed, but it can't go higher than the maximum
		if (now_ns > value.last_timestamp) {
			/* It turns out the time can go backwards. See
			   comment:
			   https://elixir.bootlin.com/linux/v4.17.11/source/kernel/time/timekeeping.c#L432
			   Let's update the delta only when time is
			   going forward. We can depleate it fine. */
			uint64_t delta = now_ns - value.last_timestamp;
			value.last_timestamp = now_ns;
			value.credit += delta;
			if (value.credit > credit_max) {
				value.credit = credit_max;
			}
		}

		// if we have more credit then than it costs, than decrease, otherwise change the verdict but leave the credit untouched (?)
		if (value.credit >= cost) {
			value.credit -= cost;
		} else {
			verdict = CREDIT_EMPTY;
		}
		/* The changes are inline. We could just do:

		*value_old = value;

		But this might cause some memory ordering
		issues. There is no compare-and-swap in ebpf
		yet. Safer to do full bpf_map_update_elem().
		 */
	}

	// try updating the map with new values
	int r = bpf_map_update_elem(map, &shkey, &value, 0);
	if (r != 0) {
		return CREDIT_ERROR;
	}
	return verdict;
}

static FORCE_INLINE int rate_limit(struct __sk_buff *skb, uint64_t now_ns, int benchmark)
{
	incr_stat(STAT_TOTAL);

	//char msg[] = "New Packet\n";
	//trace_printk(msg, sizeof(msg));

	// if not IPv4 or IPv6 quit now
	if (skb->protocol != HTONS(ETH_P_IP) &&
	    skb->protocol != HTONS(ETH_P_IPV6)) {
		incr_stat(STAT_ERROR);
		return SKB_PASS;
	}

	// define the hierarchy of groups that are going to be applied here
	struct {
		int type;
		int param_cost;
		int param_credit_max;
		void *map;
		int map_size;
		int stat_drop;
	} limits[] = {
		/* Order here is meaningful. We first want to hit the
		 * wider rate limits, and only then the more specific ones. */
		{SRC_PORT, PARAM_SOURCEPORT_COST, PARAM_SOURCEPORT_CREDIT_MAX,
		 &sourceport_limit, SOURCEPORT_SIZE, STAT_DROP_SOURCEPORT},
		{SRC_NET, PARAM_SOURCENET_COST, PARAM_SOURCENET_CREDIT_MAX,
		 &sourcenet_limit, SOURCENET_SIZE, STAT_DROP_SOURCENET},
		{SRC_IP, PARAM_SOURCE_COST, PARAM_SOURCE_CREDIT_MAX,
		 &source_limit, SOURCE_SIZE, STAT_DROP_SOURCE},
		{DST_IP_PORT, PARAM_TARGET_COST, PARAM_TARGET_CREDIT_MAX,
		 &target_limit, TARGET_SIZE, STAT_DROP_TARGET},
	};

	int verdict = CREDIT_OK;
	int stat_drop = -1;

	int i;
	// go through all our limiting groups
#pragma clang loop unroll(full)
	for (i = 0; i < (int)ARRAY_SIZE(limits); i++) {
		// get the cost per packet for this group, and if it's zero than it's free so continue
		uint64_t cost = param_get(limits[i].param_cost);
		if (cost == 0) {
			continue;
		}
		// figure out what the maximum credit is we can use for this group
		uint64_t credit_max = param_get(limits[i].param_credit_max);
		// and hash port, ip and type (type being the type of the group currently considered: SRC_PORT, SRC_NET, SRC_IP or DST_IP_PORT)
		uint64_t hash = count_hash(skb, limits[i].type);
		// figure out what to do with it
		verdict = tokenbucket_bump(limits[i].map, now_ns,
					   hash % limits[i].map_size, cost,
					   credit_max);

		// update the stat_drop variable so incase we run out of credit can report that there's a group that ran out
		stat_drop = limits[i].stat_drop;

		// if the verdict is not OK then stop looping and handle it outside of the loop
		if (!benchmark && verdict != CREDIT_OK) {
			break;
		}
	}

	switch (verdict) {
	case CREDIT_ERROR:
		// if there's an error report it but let it pass
		incr_stat(STAT_ERROR);
		return SKB_PASS;
	
	case CREDIT_EMPTY:
		// if the group ran out of credit then update the stats and reject it
		incr_stat(stat_drop);
		return SKB_REJECT;
	}

	return SKB_PASS;
}


SEC("socket_benchmark")
int bpf_rate_limit_benchmark(struct __sk_buff *skb){
	return rate_limit(skb, bpf_ktime_get_ns(), 1);
}

SEC("socket_prod")
int bpf_rate_limit_prod(struct __sk_buff *skb){
	return rate_limit(skb, bpf_ktime_get_ns(), 0);
}

// Fake time
#define SOURCEPORT_SIZE 2048
struct bpf_map_def time_map SEC("maps") = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(uint64_t),
	.max_entries = 256,
};

SEC("socket_dev")
int bpf_rate_limit_dev(struct __sk_buff *skb){
	uint64_t *t;
	uint32_t i = 0;

	t = bpf_map_lookup_elem(&time_map, &i);
	if(t){
		return rate_limit(skb, *t, 0);
	}
	return -1;
}

char __license[] SEC("license") = "Dual BSD/GPL";
