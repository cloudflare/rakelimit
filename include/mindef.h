#pragma once

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif

#ifndef offsetofend
#define offsetofend(type, member) (offsetof(type, member) + sizeof((((type *)0)->member)))
#endif
