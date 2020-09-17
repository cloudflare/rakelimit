#pragma once

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/types.h>

#include "common.h"

#define FRACTION_BITS 32

typedef __u64 fpoint;

static __u64 FORCE_INLINE to_fixed_point(__u32 n) { return ((__u64)n) << FRACTION_BITS; }

static __u32 FORCE_INLINE to_int(fpoint a) { return a >> FRACTION_BITS; }

typedef __u64 fpoint;
static fpoint FORCE_INLINE div_by_int(fpoint a, fpoint b) { return a / to_int(b); }