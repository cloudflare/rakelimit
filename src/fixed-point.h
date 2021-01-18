#pragma once

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/types.h>

#include "common.h"

#define FRACTION_BITS 32

typedef __u64 fpoint;

static __u64 FORCE_INLINE to_fixed_point(__u32 integer, __u32 fraction)
{
	return (((__u64)integer) << FRACTION_BITS) | (__u64)fraction;
}

static __u32 FORCE_INLINE to_int(fpoint a)
{
	return a >> FRACTION_BITS;
}

static fpoint FORCE_INLINE div_by_int(fpoint dividend, __u32 divisor)
{
	return dividend / divisor;
}
