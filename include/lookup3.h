/*
-------------------------------------------------------------------------------
This file is derived from lookup3 by Bob Jenkins. The main change is that
hashlittle assumes an aligned pointer. This is because BPF doesn't allow
inspecting pointer values.

lookup3.c, by Bob Jenkins, May 2006, Public Domain.

These are functions for producing 32-bit hashes for hash table lookup.
hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
are externally useful functions.  Routines to test the hash are included
if SELF_TEST is defined.  You can use this free for any purpose.  It's in
the public domain.  It has no warranty.

You probably want to use hashlittle().  hashlittle() and hashbig()
hash byte arrays.  hashlittle() is is faster than hashbig() on
little-endian machines.  Intel and AMD are little-endian machines.
On second thought, you probably want hashlittle2(), which is identical to
hashlittle() except it returns two 32-bit hashes for the price of one.
You could implement hashbig2() if you wanted but I haven't bothered here.

If you want to find a hash of, say, exactly 7 integers, do
  a = i1;  b = i2;  c = i3;
  mix(a,b,c);
  a += i4; b += i5; c += i6;
  mix(a,b,c);
  a += i7;
  final(a,b,c);
then use c as the hash value.  If you have a variable length array of
4-byte integers to hash, use hashword().  If you have a byte array (like
a character string), use hashlittle().  If you have several byte arrays, or
a mix of things, see the comments above hashlittle().

Why is this so big?  I read 12 bytes at a time into 3 4-byte integers,
then mix those integers.  This is fast (you can do a lot more thorough
mixing with 12*3 instructions on 3 integers than you can with 3 instructions
on 1 byte), but shoehorning those bytes into integers efficiently is messy.
-------------------------------------------------------------------------------
*/

#pragma once

#include <linux/types.h>

// clang-format off

#define hashsize(n) ((__u32)1 << (n))
#define hashmask(n) (hashsize(n) - 1)
#define rot(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

/*
-------------------------------------------------------------------------------
mix -- mix 3 32-bit values reversibly.

This is reversible, so any information in (a,b,c) before mix() is
still in (a,b,c) after mix().

If four pairs of (a,b,c) inputs are run through mix(), or through
mix() in reverse, there are at least 32 bits of the output that
are sometimes the same for one pair and different for another pair.
This was tested for:
* pairs that differed by one bit, by two bits, in any combination
  of top bits of (a,b,c), or in any combination of bottom bits of
  (a,b,c).
* "differ" is defined as +, -, ^, or ~^.  For + and -, I transformed
  the output delta to a Gray code (a^(a>>1)) so a string of 1's (as
  is commonly produced by subtraction) look like a single 1-bit
  difference.
* the base values were pseudorandom, all zero but one bit set, or
  all zero plus a counter that starts at zero.

Some k values for my "a-=c; a^=rot(c,k); c+=b;" arrangement that
satisfy this are
	4  6  8 16 19  4
	9 15  3 18 27 15
   14  9  3  7 17  3
Well, "9 15 3 18 27 15" didn't quite get 32 bits diffing
for "differ" defined as + with a one-bit base and a two-bit delta.  I
used http://burtleburtle.net/bob/hash/avalanche.html to choose
the operations, constants, and arrangements of the variables.

This does not achieve avalanche.  There are input bits of (a,b,c)
that fail to affect some output bits of (a,b,c), especially of a.  The
most thoroughly mixed value is c, but it doesn't really even achieve
avalanche in c.

This allows some parallelism.  Read-after-writes are good at doubling
the number of bits affected, so the goal of mixing pulls in the opposite
direction as the goal of parallelism.  I did what I could.  Rotates
seem to cost as much as shifts on every machine I could lay my hands
on, and rotates are much kinder to the top and bottom bits, so I used
rotates.
-------------------------------------------------------------------------------
*/
#define mix(a, b, c) \
	{ \
		a -= c; \
		a ^= rot(c, 4); \
		c += b; \
		b -= a; \
		b ^= rot(a, 6); \
		a += c; \
		c -= b; \
		c ^= rot(b, 8); \
		b += a; \
		a -= c; \
		a ^= rot(c, 16); \
		c += b; \
		b -= a; \
		b ^= rot(a, 19); \
		a += c; \
		c -= b; \
		c ^= rot(b, 4); \
		b += a; \
	}

/*
-------------------------------------------------------------------------------
final -- final mixing of 3 32-bit values (a,b,c) into c

Pairs of (a,b,c) values differing in only a few bits will usually
produce values of c that look totally different.  This was tested for
* pairs that differed by one bit, by two bits, in any combination
  of top bits of (a,b,c), or in any combination of bottom bits of
  (a,b,c).
* "differ" is defined as +, -, ^, or ~^.  For + and -, I transformed
  the output delta to a Gray code (a^(a>>1)) so a string of 1's (as
  is commonly produced by subtraction) look like a single 1-bit
  difference.
* the base values were pseudorandom, all zero but one bit set, or
  all zero plus a counter that starts at zero.

These constants passed:
 14 11 25 16 4 14 24
 12 14 25 16 4 14 24
and these came close:
  4  8 15 26 3 22 24
 10  8 15 26 3 22 24
 11  8 15 26 3 22 24
-------------------------------------------------------------------------------
*/
#define final(a, b, c) \
	{ \
		c ^= b; \
		c -= rot(b, 14); \
		a ^= c; \
		a -= rot(c, 11); \
		b ^= a; \
		b -= rot(a, 25); \
		c ^= b; \
		c -= rot(b, 16); \
		a ^= c; \
		a -= rot(c, 4); \
		b ^= a; \
		b -= rot(a, 14); \
		c ^= b; \
		c -= rot(b, 24); \
	}

static __attribute__((always_inline)) __u32 hashlittle(const void *key, __u64 length, __u32 initval)
{
	__u32 a, b, c;                       /* internal state */
	const __u32 *k = (const __u32 *)key; /* read 32-bit chunks */
	const __u32 *end = k + (length / 12) * 3;
	const __u8 *k8;

	/* Set up the internal state */
	a = b = c = 0xdeadbeef + ((__u32)length) + initval;

	/*------ all but last block: aligned reads and affect 32 bits of (a,b,c) */
#pragma clang loop unroll(full)
	while (k != end) {
		a += k[0];
		b += k[1];
		c += k[2];
		mix(a, b, c);
		k += 3;
	}

	/*----------------------------- handle the last (probably partial) block */
	k8 = (const __u8 *)k;
	switch (length % 12) {
	case 12:
		c += k[2];
		b += k[1];
		a += k[0];
		break;
	case 11:
		c += ((__u32)k8[10]) << 16; /* fall through */
	case 10:
		c += ((__u32)k8[9]) << 8; /* fall through */
	case 9:
		c += k8[8]; /* fall through */
	case 8:
		b += k[1];
		a += k[0];
		break;
	case 7:
		b += ((__u32)k8[6]) << 16; /* fall through */
	case 6:
		b += ((__u32)k8[5]) << 8; /* fall through */
	case 5:
		b += k8[4]; /* fall through */
	case 4:
		a += k[0];
		break;
	case 3:
		a += ((__u32)k8[2]) << 16; /* fall through */
	case 2:
		a += ((__u32)k8[1]) << 8; /* fall through */
	case 1:
		a += k8[0];
		break;
	case 0:
		return c;
	}

	final(a, b, c);
	return c;
}

#undef hashsize
#undef hashmask
#undef rot
#undef mix
#undef final
