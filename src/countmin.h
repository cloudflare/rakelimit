#pragma once
#include <linux/bpf.h>
#include <stddef.h>
#include <types.h>

#include "common.h"
#include "ewma.h"
#include "fasthash.h"
#include "fixed-point.h"
#include "packet_element.h"

// countmin sketch paper: http://dimacs.rutgers.edu/~graham/pubs/papers/cm-full.pdf
// the error in answering the query is within an error epsilon with probability (1-gamma) (page 5, 6)
//
// e = base of the natural logarithm ln = ~2.72
// columns = e / epsilon, epsilon = ~0.01 --> columns = 271 (rounded slightly down to a power of two) = ~256
// --> e / 256 = ~0.010625
// hashfn_n = ln 1/gamma, gamma = 0.01 --> hashfn_n = ~5

#define HASHFN_N 5
#define COLUMNS 256

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

struct cm_value {
	fpoint value;
	__u64 ts;
} __attribute__((packed));

struct countmin {
	struct cm_value values[HASHFN_N][COLUMNS];
} __attribute__((packed));

// add element and determine count
static __u64 FORCE_INLINE add_to_cm(struct countmin *cm, __u64 ts, struct packet_element *element)
{
	fpoint min = -1;
#pragma clang loop unroll(full)
	for (int i = 0; i < HASHFN_N; i++) {
		__u32 target_idx       = fasthash64(element, sizeof(struct packet_element), i) & (COLUMNS - 1);
		struct cm_value *value = &cm->values[i][target_idx];
		value->value           = estimate_avg_rate(value->value, ts - value->ts);
		value->ts = ts;
		if (value->value < min) {
			min = value->value;
		}
	}
	return min;
} 