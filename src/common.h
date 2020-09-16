#define FORCE_INLINE inline __attribute__((__always_inline__))

/* from linux/socket.h */
#define AF_INET 2   /* Internet IP Protocol 	*/
#define AF_INET6 10 /* IP version 6			*/
/***********************/

/* from linux/filter.h */
#define BPF_NET_OFF (-0x100000)
#define BPF_LL_OFF (-0x200000)
/***********************/

/* Accept - allow any number of bytes */
#define SKB_PASS -1
/* Drop, cut packet to zero bytes */
#define SKB_REJECT 0

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD