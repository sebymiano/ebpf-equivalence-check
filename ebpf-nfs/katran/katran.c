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

#ifndef USES_BPF_GET_SMP_PROC_ID
#define USES_BPF_GET_SMP_PROC_ID
#endif

#ifndef USES_BPF_KTIME_GET_NS
#define USES_BPF_KTIME_GET_NS
#endif

#ifndef USES_BPF_XDP_ADJUST_HEAD
#define USES_BPF_XDP_ADJUST_HEAD
#endif

#ifndef USES_BPF_CSUM_DIFF
#define USES_BPF_CSUM_DIFF
#endif

#include "katran_pkts.h"

int main(int argc, char** argv){
  OPENED_INIT(argc, argv);

  BPF_MAP_INIT(&vip_map, "vip_map", "pkt.vip", "vip_metadata");
  BPF_MAP_OF_MAPS_INIT(&lru_mapping, &fallback_cache, "lru_mapping", "fallback_cache", "pkt.flow", "backend");
  BPF_MAP_INIT(&fallback_cache, "fallback_cache", "pkt.flow", "backend");
  BPF_MAP_INIT(&ch_rings, "ch_rings", "", "backend_real_id");
  BPF_MAP_INIT(&reals, "reals", "", "backend_metadata");
  BPF_MAP_INIT(&reals_stats, "reals_stats", "", "backend_stats");
  BPF_MAP_INIT(&stats, "stats", "", "vip_stats");
  BPF_MAP_INIT(&quic_mapping, "quic_mapping", "", "backend_real_id");
  BPF_MAP_INIT(&ctl_array, "ctl_array", "", "backend_mac_addrs");

  BPF_MAP_RESET(&reals);
  BPF_MAP_RESET(&reals_stats);
  BPF_MAP_RESET(&stats);
  BPF_MAP_RESET(&quic_mapping);
  BPF_MAP_RESET(&ctl_array);

  #ifdef LPM_SRC_LOOKUP
  BPF_MAP_INIT(lpm_src_v4);
  BPF_MAP_INIT(lpm_src_v6);
  #endif

  struct xdp_md test;
  if(klee_int("pkt.isIPv4")){
    if(klee_int("pkt.is_fragmented"))
      get_packet(FRAGV4,&test);
    else if(klee_int("pkt.isICMP"))
      get_packet(ICMPV4,&test);
    else
      get_packet(IPV4,&test);
  }
  else if(klee_int("pkt.isIPv6")) {
    // ipv6
    if(klee_int("pkt.is_fragmented"))
      get_packet(FRAGV6,&test);
    else if(klee_int("pkt.isICMP"))
      get_packet(ICMPV6,&test); 
    else
      get_packet(IPV6,&test);
  }
  else{
    get_packet(NON_IP,&test);
  }

  test.data_meta = 0;
  
  __u32 temp = 0;
  klee_make_symbolic(&(temp), sizeof(temp), "ingress_ifindex");
  test.ingress_ifindex = temp;

  test.rx_queue_index = 0;

  int ret;
  bpf_begin();
  if (balancer_ingress(&test)) {
    ret = 1;
  } else {
    ret = 0;
  }
  
  OPENED_CLOSE();
  return ret;
}

