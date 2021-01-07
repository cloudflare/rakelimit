#pragma once

#include <linux/types.h>

#include "common.h"
#include "fixed-point.h"

// 100ms
#define WINDOW_NS 100000000ull
#define ONE_SECOND_NS 1000000000ull

// estimate_avg_rate takes a previous rate and a duration that elapsed
// since this rate has been determined, and estimates based on these and
// WINDOW the current rate in packets per second.
static __u32 FORCE_INLINE estimate_rate(__u32 old_rate, __u64 old_ts, __u64 now)
{
	if (old_ts >= now) {
		// Time went backward or stood still due to clockskew. Return the old value,
		// since we can't compute the current rate.
		return old_rate;
	}

	__s64 elapsed = now - old_ts;
	if (old_ts == 0 || elapsed >= WINDOW_NS) {
		// Either there is no previous measurement, or it's too old.
		// We need another sample to calculate a reliable rate.
		return 0;
	}

	__u32 rate_current = ONE_SECOND_NS / elapsed;
	if (old_rate == 0) {
		// This is the first time we can calculate a rate, so use that
		// to initialize our estimate.
		return rate_current;
	}

	fpoint a        = div_by_int(to_fixed_point(elapsed, 0), WINDOW_NS);
	fpoint new_rate = to_fixed_point(rate_current, 0);

	if (old_rate > rate_current) {
		new_rate -= a * (old_rate - rate_current);
	} else {
		new_rate += a * (rate_current - old_rate);
	}

	return to_int(new_rate);
}