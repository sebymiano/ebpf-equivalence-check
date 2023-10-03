/* Driver for klee verification */
#include "klee/klee.h"
#include <stdlib.h>

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

#ifndef USES_BPF_MAP_UPDATE_ELEM
#define USES_BPF_MAP_UPDATE_ELEM
#endif

#ifndef USES_BPF_REDIRECT_MAP
#define USES_BPF_REDIRECT_MAP
#endif

#ifndef USES_BPF_XDP_ADJUST_HEAD
#define USES_BPF_XDP_ADJUST_HEAD
#endif


#include "klee_xdp_test.h"

struct __attribute__((__packed__)) pkt_eth {
  char prev_buf[500];
  struct ethhdr eth;
  char fwd_buff[500];
};

struct __attribute__((__packed__)) pkt_vlan {
  char prev_buff[500];
  struct ethhdr eth;
  struct vlan_hdr vlh;
  char fwd_buff[500];
};

/*
#ifdef USES_BPF_XDP_ADJUST_HEAD
static __attribute__((noinline)) int bpf_xdp_adjust_head(struct xdp_md *xdp_md, int delta) {
  // Simple stub for now that only moves data pointer without a check. We assume
  // programs don't use the metadata for now
  if(record_calls){
    klee_trace_ret();
    klee_add_bpf_call();
  }
  xdp_md->data += delta;
  return 0;
}
#else 
static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
  (void *) BPF_FUNC_xdp_adjust_head;
#endif
*/

int main(int argc, char** argv){

  struct xdp_md test_ctx;

  if (klee_int("pkt.isVLAN")) {
    struct pkt_vlan *pkt = malloc(sizeof(struct pkt_vlan));
    klee_make_symbolic(pkt, sizeof(struct pkt_vlan), "vlan_pkt");

    /* Make this a vlan packet. */
    pkt->eth.h_proto = bpf_htons(ETH_P_8021Q);
    klee_assume((pkt->eth.h_proto == bpf_htons(ETH_P_8021Q)) ||
                 (pkt->eth.h_proto == bpf_htons(ETH_P_8021AD)));

    /* Make sure this is not an invalid vlan packet. */
    klee_assume((bpf_ntohs(pkt->vlh.h_vlan_TCI) > 0) &&
                (bpf_ntohs(pkt->vlh.h_vlan_TCI) < 4095));

    test_ctx.data = (long)(&(pkt->eth));
    test_ctx.data_end = (long)(pkt + 1);
 } else {
    struct pkt_eth *pkt = malloc(sizeof(struct pkt_eth));
    klee_make_symbolic(pkt, sizeof(struct pkt_eth), "eth_pkt");

    // Make sure this is not a vlan packet.
    klee_assume((pkt->eth.h_proto != bpf_htons(ETH_P_8021Q)) && 
                (pkt->eth.h_proto != bpf_htons(ETH_P_8021AD)));
    test_ctx.data = (long)(&(pkt->eth));
    test_ctx.data_end = (long)(pkt + 1);
  }

  test_ctx.data_meta = 0;

  __u32 ingress_interface = 0;
  //  klee_make_symbolic(&(ingress_interface), sizeof(ingress_interface), "ingress_ifindex");
  test_ctx.ingress_ifindex = ingress_interface;

  test_ctx.rx_queue_index = 0;

  bpf_begin();
  if (xdp_vlan_swap_func(&test_ctx))
    return 1;
  return 0;
}