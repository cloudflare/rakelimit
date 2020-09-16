#pragma once
#include "common.h"
#include "fixed-point.h"
#include <types.h>

#define WINDOW 1000000000ull

// estimate_avg_rate takes a previous rate and a duration that elapsed
// since this rate has been determined, and estimates based on these and
// WINDOW the current rate in packets per second.
static fpoint FORCE_INLINE estimate_avg_rate(fpoint old_rate, __s64 dur)
{
	// if nothing changed or
	if (dur <= 0) {
		return old_rate;
	}

	// calculate pps since last timestamp
	__u64 rate_current = 1000000000ull / dur;
	// if the last timestamp is older than the window the new pps will simply be rate_current
	if (dur >= WINDOW) {
		return to_fixed_point(rate_current);
	}

	fpoint a = to_fixed_point(dur) / WINDOW;

	fpoint new_rate = old_rate;
	if (old_rate > to_fixed_point(rate_current)) {
		new_rate -= a * to_int(old_rate - to_fixed_point(rate_current));
	} else {
		new_rate += a * to_int(to_fixed_point(rate_current) - old_rate);
	}
	return new_rate;
}