#pragma once
// #define FORCE_INLINE inline __attribute__((__always_inline__))
#define FORCE_INLINE __attribute__((noinline))

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

#if (defined KLEE_VERIFICATION)
unsigned long long load_byte(struct __sk_buff *skb, unsigned long long off) {
    void *data = (void*)(long)skb->data;
    return (__u8)(data + off);
}
unsigned long long load_half(struct __sk_buff *skb, unsigned long long off) {
    void *data = (void*)(long)skb->data;
    return (__u16)(data + off);
}
unsigned long long load_word(struct __sk_buff *skb, unsigned long long off) {
    void *data = (void*)(long)skb->data;
    return (__u32)(data + off);
}
#else
unsigned long long load_byte(void *skb, unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb, unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb, unsigned long long off) asm("llvm.bpf.load.word");
#endif

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))