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
static fpoint FORCE_INLINE estimate_avg_rate(fpoint old_rate, __u64 old_ts, __u64 now)
{
	__s64 elapsed = now - old_ts;
	if (elapsed <= 0) {
		// Time went backward or stood still due to clockskew. Return the old value,
		// since we can't compute the current rate.
		return old_rate;
	}

	if (old_ts == 0 || elapsed >= WINDOW_NS) {
		// Either there is no previous measurement, or it's too old.
		// We need another sample to calculate a reliable rate.
		return 0;
	}

	fpoint rate_current = to_fixed_point(ONE_SECOND_NS / elapsed, 0);
	if (old_rate == 0) {
		// This is the first time we can calculate a rate, so use that
		// to initialize our estimate.
		return rate_current;
	}

	fpoint a = to_fixed_point(elapsed, 0) / WINDOW_NS;

	fpoint new_rate = old_rate;
	if (old_rate > rate_current) {
		new_rate -= a * to_int(old_rate - rate_current);
	} else {
		new_rate += a * to_int(rate_current - old_rate);
	}
	return new_rate;
}