#pragma once
#include <linux/bpf.h>
#include <linux/types.h>
#include <mindef.h>

#include "common.h"
#include "ewma.h"
#include "fasthash.h"
#include "fixed-point.h"
#include "lookup3.h"

// countmin sketch paper: http://dimacs.rutgers.edu/~graham/pubs/papers/cm-full.pdf
//
// A cm sketch can be thought of as a two dimensional array width d rows and
// w columns. Each row uses a distinct hash function to index into its columns.
//
// The paper shows the following error bounds for the estimation, provided we
// choose d = ceil(ln(1/gamma)) and w = ceil(e/E) (see page 7).
//
//     a  <= a'
//     a' <= E * ||a||          with probability at least (1 - gamma)
//     a    : the true answer
//     a'   : the estimate made by the cm sketch
//     E    : a chosen error bound
//     gamma: desired probability of the upper bound
//     ||a||: the sum of all previous observations (I think)
//
// We always choose w to be a power of two to be able to cheaply index into the cm
// sketch based on a hash value. For d = 2 and w = 512 we get gamma ~0.14 and E ~0.005.
//
//     a <= a' <= ~0.005 * ||a|| (with probability ~0.86)
//
// Using 3 instead of 2 hash functions would increase the probability to 0.96. For
// that we need another function however.

#define HASHFN_N 2
#define COLUMNS 512

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

struct cm_value {
	__u32 value;
	__u64 ts;
};

struct countmin {
	struct cm_value values[HASHFN_N][COLUMNS];
};

// add element and determine count
static __u32 FORCE_INLINE cm_add_and_query(struct countmin *cm, __u64 now, void *element, __u64 len)
{
	const __u32 hashes[] = {
		fasthash32(element, len, 0x2d31e867),
		hashlittle(element, len, 0x6ad611c4),
	};

	_Static_assert(ARRAY_SIZE(hashes) == HASHFN_N, "Missing hash function");

	fpoint min = -1;
#pragma clang loop unroll(full)
	for (int i = 0; i < ARRAY_SIZE(hashes); i++) {
		__u32 target_idx       = hashes[i] & (COLUMNS - 1);
		struct cm_value *value = &cm->values[i][target_idx];
		value->value           = estimate_rate(value->value, value->ts, now);
		value->ts              = now;
		if (value->value < min) {
			min = value->value;
		}
	}
	return min;
}
