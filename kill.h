/* SPDX-License-Identifier: MIT */
#ifndef KILL_H
#define KILL_H

#include <regex.h>
#include <stdbool.h>

#include "meminfo.h"

typedef struct {
    /* if the available memory AND swap goes below these percentages,
     * we start killing processes. Derived from the options below by
     * derive_thresholds(), which has to run again whenever the memory
     * totals change - a cgroup limit can appear, disappear or be resized
     * while we are running. */
    double mem_term_percent;
    double mem_kill_percent;
    double swap_term_percent;
    double swap_kill_percent;
    /* Percentages as passed to -m/-s */
    double opt_mem_term_percent;
    double opt_mem_kill_percent;
    double opt_swap_term_percent;
    double opt_swap_kill_percent;
    /* Absolute sizes as passed to -M/-S, in KiB. Only used when the
     * matching have_* flag is set. */
    double opt_mem_term_kib;
    double opt_mem_kill_kib;
    double opt_swap_term_kib;
    double opt_swap_kill_kib;
    bool have_m;
    bool have_M;
    bool have_s;
    bool have_S;
    /* The totals opt_*_kib were last converted against */
    long long derived_mem_total_kib;
    long long derived_swap_total_kib;
    /* send d-bus notifications? */
    bool notify;
    /* Path to script for programmatic notifications (or NULL) */
    char* notify_ext;
    /* kill all processes within a process group */
    bool kill_process_group;
    /* do not kill processes owned by root */
    bool ignore_root_user;
    /* find process with the largest rss */
    bool sort_by_rss;
    /* prefer/avoid killing these processes. NULL = no-op. */
    regex_t* prefer_regex;
    regex_t* avoid_regex;
    /* will ignore these processes. NULL = no-op. */
    regex_t* ignore_regex;
    /* memory report interval, in milliseconds */
    int report_interval_ms;
    /* minimal interval between checks */
    unsigned min_sleep_ms;
    /* maximum interval between checks */
    unsigned max_sleep_ms;
    /* Flag --dryrun was passed */
    bool dryrun;
} poll_loop_args_t;

void kill_process(const poll_loop_args_t* args, int sig, const procinfo_t* victim);
procinfo_t find_largest_process(const poll_loop_args_t* args);
bool is_larger(const poll_loop_args_t* args, const procinfo_t* victim, procinfo_t* cur);

#endif
