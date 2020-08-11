#pragma once

typedef unsigned long long uint64_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

_Static_assert(sizeof(uint64_t) == 8, "uint64_t size is wrong");
_Static_assert(sizeof(uint32_t) == 4, "uint32_t size is wrong");
_Static_assert(sizeof(uint16_t) == 2, "uint16_t size is wrong");
_Static_assert(sizeof(uint8_t) == 1, "uint8_t size is wrong");

typedef unsigned long long size_t;

_Static_assert(sizeof(size_t) == 8, "size_t size is wrong");
