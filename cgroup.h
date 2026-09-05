/* SPDX-License-Identifier: MIT */
#ifndef CGROUP_H
#define CGROUP_H

#include <stdbool.h>

#include "meminfo.h"

/* Set by --no-cgroup. When true, cgroup_meminfo() is a no-op and earlyoom
 * always looks at the host-wide numbers from /proc/meminfo. */
extern bool cgroup_disabled;

/* Set by --cgroup. Skips the sanity check that refuses a limit which does
 * not cover the processes earlyoom sees in /proc. */
extern bool cgroup_forced;

/* If earlyoom lives in a cgroup that has a memory limit (a container, a
 * Kubernetes pod, a systemd unit with MemoryMax=, ...), overwrite the
 * host-wide values in `m` with the ones of that cgroup.
 *
 * Only MemTotalKiB, MemAvailableKiB and AnonPagesKiB (and, if the cgroup
 * also limits swap, SwapTotalKiB and SwapFreeKiB) are touched; the caller
 * is responsible for recalculating the derived values afterwards.
 *
 * Returns true if `m` was modified. */
bool cgroup_meminfo(meminfo_t* m);

/* Check the limit we found against the process earlyoom would kill right
 * now: `pid` is what find_largest_process() picked and `rss_kib` its size.
 * Turns cgroup mode back off if that process is not covered by the limit,
 * which is what happens when earlyoom runs on a node with hostPID but has a
 * memory limit of its own. Call this once, after option parsing. */
void cgroup_verify_victim(int pid, long long rss_kib);

/* Path of the cgroup whose limit we are using, or NULL when we are not
 * limited by any cgroup. Only meaningful after cgroup_meminfo() ran. */
const char* cgroup_dir(void);

/* Forget the cached detection results. Used by the test suite. */
void cgroup_reset(void);

#endif
