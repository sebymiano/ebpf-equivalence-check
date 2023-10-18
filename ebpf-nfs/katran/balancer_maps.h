/* Copyright (C) 2018-present, Facebook, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __BALANCER_MAPS_H
#define __BALANCER_MAPS_H

/*
 * This file contains definition of maps used by the balancer typically
 * involving information pertaining to proper forwarding of packets
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "balancer_consts.h"
#include "balancer_structs.h"

// map, which contains all the vips for which we are doing load balancing
#if defined KLEE_VERIFICATION
struct bpf_map_def SEC("maps") vip_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct vip_definition),
  .value_size = sizeof(struct vip_meta),
  .max_entries = MAX_VIPS,
  .map_flags = NO_FLAGS,
  .map_id = -1,
};
#ifndef OPENED_EQUIVALENCE
BPF_ANNOTATE_KV_PAIR(vip_map, struct vip_definition, struct vip_meta);
#endif
#else 
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct vip_definition);
    __type(value, struct vip_meta);
    __uint(max_entries, MAX_VIPS);
    __uint(map_flags, NO_FLAGS);
} vip_map SEC(".maps");
#endif

#if defined KLEE_VERIFICATION
// map which contains cpu core to lru mapping
struct bpf_map_def SEC("maps") lru_mapping = {
  .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = MAX_SUPPORTED_CPUS,
  .map_flags = NO_FLAGS,
  .map_id = -1,
};
#else
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_SUPPORTED_CPUS);
    __uint(map_flags, NO_FLAGS);
    __array(
      values,
      struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __type(key, struct flow_key);
        __type(value, struct real_pos_lru);
        __uint(max_entries, DEFAULT_LRU_SIZE);
      });
} lru_mapping SEC(".maps");
#endif

#if defined KLEE_VERIFICATION
// fallback lru. we should never hit this one outside of unittests
struct bpf_map_def SEC("maps") fallback_cache = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(struct flow_key),
  .value_size = sizeof(struct real_pos_lru),
  .max_entries = DEFAULT_LRU_SIZE,
  .map_flags = NO_FLAGS,
  .map_id = -1,
};

#ifndef OPENED_EQUIVALENCE
BPF_ANNOTATE_KV_PAIR(fallback_cache, struct flow_key, struct real_pos_lru);
#endif
#else
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct real_pos_lru);
    __uint(max_entries, DEFAULT_LRU_SIZE);
    __uint(map_flags, NO_FLAGS);
} fallback_cache SEC(".maps");
#endif

#if defined KLEE_VERIFICATION
// map which contains all vip to real id mappings
struct bpf_map_def SEC("maps") ch_rings = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = CH_RINGS_SIZE,
  .map_flags = NO_FLAGS,
  .map_id = -1,
};
#ifndef OPENED_EQUIVALENCE
BPF_ANNOTATE_KV_PAIR(ch_rings, __u32, __u32);
#endif
#else
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, CH_RINGS_SIZE);
    __uint(map_flags, NO_FLAGS);
} ch_rings SEC(".maps");
#endif

#if defined KLEE_VERIFICATION
// map which contains opaque real's id to real definition mapping
struct bpf_map_def SEC("maps") reals = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct real_definition),
  .max_entries = MAX_REALS,
  .map_flags = NO_FLAGS,
  .map_id = -1,
};
#ifndef OPENED_EQUIVALENCE
BPF_ANNOTATE_KV_PAIR(reals, __u32, struct real_definition);
#endif
#else
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct real_definition);
    __uint(max_entries, MAX_REALS);
    __uint(map_flags, NO_FLAGS);
} reals SEC(".maps");
#endif

#if defined KLEE_VERIFICATION
// map with per real pps/bps statistic
struct bpf_map_def SEC("maps") reals_stats = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct lb_stats),
  .max_entries = MAX_REALS,
  .map_flags = NO_FLAGS,
  .map_id = -1,
};
#ifndef OPENED_EQUIVALENCE
BPF_ANNOTATE_KV_PAIR(reals_stats, __u32, struct lb_stats);
#endif
#else
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct lb_stats);
    __uint(max_entries, MAX_REALS);
    __uint(map_flags, NO_FLAGS);
} reals_stats SEC(".maps");
#endif

#if defined KLEE_VERIFICATION
// map w/ per vip statistics
struct bpf_map_def SEC("maps") stats = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct lb_stats),
  .max_entries = STATS_MAP_SIZE,
  .map_flags = NO_FLAGS,
  .map_id = -1,
};
#ifndef OPENED_EQUIVALENCE
BPF_ANNOTATE_KV_PAIR(stats, __u32, struct lb_stats);
#endif
#else
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct lb_stats);
    __uint(max_entries, STATS_MAP_SIZE);
    __uint(map_flags, NO_FLAGS);
} stats SEC(".maps");
#endif

#if defined KLEE_VERIFICATION
// map for quic connection-id to real's id mapping
struct bpf_map_def SEC("maps") quic_mapping = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = MAX_REALS,
  .map_flags = NO_FLAGS,
  .map_id = -1,
};
#ifndef OPENED_EQUIVALENCE
BPF_ANNOTATE_KV_PAIR(quic_mapping, __u32, __u32);
#endif
#else
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_REALS);
    __uint(map_flags, NO_FLAGS);
} quic_mapping SEC(".maps");
#endif

#ifdef LPM_SRC_LOOKUP
#if defined KLEE_VERIFICATION
struct bpf_map_def SEC("maps") lpm_src_v4 = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct v4_lpm_key),
  .value_size = sizeof(__u32),
  .max_entries = MAX_LPM_SRC,
  .map_flags = BPF_F_NO_PREALLOC,
  .map_id = -1,
};
#ifndef OPENED_EQUIVALENCE
BPF_ANNOTATE_KV_PAIR(lpm_src_v4, struct v4_lpm_key, __u32);
#endif
#else
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct v4_lpm_key);
    __type(value, __u32);
    __uint(max_entries, MAX_LPM_SRC);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_src_v4 SEC(".maps");
#endif

#if defined KLEE_VERIFICATION
struct bpf_map_def SEC("maps") lpm_src_v6 = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct v6_lpm_key),
  .value_size = sizeof(__u32),
  .max_entries = MAX_LPM_SRC,
  .map_flags = BPF_F_NO_PREALLOC,
  .map_id = -1,
};
#ifndef OPENED_EQUIVALENCE
BPF_ANNOTATE_KV_PAIR(lpm_src_v6, struct v6_lpm_key, __u32);
#endif
#else
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct v6_lpm_key);
    __type(value, __u32);
    __uint(max_entries, MAX_LPM_SRC);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_src_v6 SEC(".maps");
#endif

#endif

#endif // of _BALANCER_MAPS
