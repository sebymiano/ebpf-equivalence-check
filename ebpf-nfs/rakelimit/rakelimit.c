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

#ifndef USES_BPF_GET_PRANDOM_U32
#define USES_BPF_GET_PRANDOM_U32
#endif

#ifndef USES_BPF_CSUM_DIFF
#define USES_BPF_CSUM_DIFF
#endif

#include "rakelimit_kern.h"

struct __attribute__((__packed__)) rakelimit_pkt {
  char payload[1500];
};

int main(int argc, char** argv){
  OPENED_INIT(argc, argv);

  BPF_MAP_INIT(&stats, "stats", "stats_key", "stats_value");
  BPF_MAP_INIT(&countmin, "countmin", "countmin_key", "countmin_value");

  BPF_MAP_RESET(&stats);
  BPF_MAP_RESET(&countmin);

  struct __sk_buff test;
  
  struct rakelimit_pkt *pkt = malloc(sizeof(struct rakelimit_pkt));
  klee_make_symbolic(pkt, sizeof(struct rakelimit_pkt), "user_buf");

  test.data = (long)(&(pkt->payload[0]));
  test.data_end = (long)(pkt + 1);
  
  __u32 temp = 0;
  klee_make_symbolic(&(temp), sizeof(temp), "ingress_ifindex");
  test.ingress_ifindex = temp;

//   test.rx_queue_index = 0;

  int ret;
  bpf_begin();
  if (filter_ipv4(&test)) {
    ret = 1;
  } else {
    ret = 0;
  }
  
  OPENED_CLOSE();
  return ret;
}