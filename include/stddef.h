#pragma once

#define NULL ((void *)0)

#define offsetof(type, member) __builtin_offsetof(type, member)
#define offsetofend(type, member) (offsetof(type, member) + sizeof((((type *)0)->member)))
