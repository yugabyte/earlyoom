// SPDX-License-Identifier: MIT

/* Read the memory limit of the cgroup earlyoom runs in.
 *
 * Inside a container - a Kubernetes pod, for example - /proc/meminfo still
 * shows the memory of the whole machine, so earlyoom would happily watch
 * 64 GiB of node memory while the pod gets OOM-killed at its 2 GiB limit
 * (https://github.com/rfjakob/earlyoom/issues/331). If we find a memory
 * limit on our own cgroup we use that instead.
 *
 * Both cgroup v1 (memory.limit_in_bytes) and v2 (memory.max) are supported.
 * When no limit is in effect we stay with the host-wide numbers.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cgroup.h"
#include "globals.h"
#include "meminfo.h"
#include "msg.h"

bool cgroup_disabled = false;
bool cgroup_forced = false;

/* "no limit". cgroup v2 spells this "max", v1 uses a huge number. */
#define CGROUP_UNLIMITED LLONG_MAX
/* Return value of the parse helpers when the value could not be read. */
#define CGROUP_ERR -1
/* Cgroup paths get long. Kubernetes produces things like
 * /sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uuid>.slice/cri-containerd-<sha256>.scope
 * which is already past PATH_LEN. */
#define CGROUP_PATH_LEN 512

enum cgroup_state {
    CGROUP_UNPROBED = 0,
    CGROUP_ACTIVE,
    CGROUP_INACTIVE,
};

static struct {
    enum cgroup_state state;
    bool v2;
    /* Root of the memory hierarchy: "/sys/fs/cgroup" (v2) or
     * "/sys/fs/cgroup/memory" (v1) */
    char base[CGROUP_PATH_LEN];
    /* The cgroup that imposes the limit we watch. Somewhere at or above
     * the cgroup earlyoom itself lives in. */
    char dir[CGROUP_PATH_LEN];
    /* Its limit, as found by probe() */
    long long limit_kib;
} cg;

/* Concatenate `a`, `b` and `c` into `out`. Returns false if the result did
 * not fit, in which case `out` must not be used.
 * `out` must not alias any of the inputs. */
static bool join_path(char* out, size_t outlen, const char* a, const char* b, const char* c)
{
    int n = snprintf(out, outlen, "%s%s%s", a, b, c);
    if (n < 0 || (size_t)n >= outlen) {
        warn("%s: path '%s%s%s' is too long\n", __func__, a, b, c);
        return false;
    }
    return true;
}

/* Read the whole content of `path` into `buf` and null-terminate it.
 * Uses raw syscalls so that we do not allocate memory in the poll loop.
 * Returns 0 on success and -errno on error. */
static int read_file(const char* path, char* buf, size_t buflen)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -errno;
    }
    ssize_t n = read(fd, buf, buflen - 1);
    int read_errno = errno;
    close(fd);
    if (n < 0) {
        return -read_errno;
    }
    buf[n] = 0;
    return 0;
}

/* Parse the content of a single-value cgroup file, which holds either a
 * byte count or (v2) the literal string "max".
 * Returns the value in bytes, CGROUP_UNLIMITED, or CGROUP_ERR. */
static long long parse_cgroup_value(const char* buf)
{
    if (strncmp(buf, "max", 3) == 0) {
        return CGROUP_UNLIMITED;
    }
    errno = 0;
    char* end = NULL;
    long long val = strtoll(buf, &end, 10);
    if (errno != 0 || end == buf || val < 0) {
        return CGROUP_ERR;
    }
    /* cgroup v1 has no "max" keyword and stores "unlimited" as
     * PAGE_COUNTER_MAX (9223372036854771712 on 64 bit). Nobody limits a
     * cgroup to four exabytes, so treat anything up there as unlimited. */
    if (val > (1LL << 62)) {
        return CGROUP_UNLIMITED;
    }
    return val;
}

/* Read a single-value cgroup file below `dir`.
 * Returns the value in bytes, CGROUP_UNLIMITED, or CGROUP_ERR. */
static long long read_cgroup_value(const char* dir, const char* name)
{
    char path[CGROUP_PATH_LEN] = { 0 };
    char buf[64] = { 0 };

    if (!join_path(path, sizeof(path), dir, "/", name)) {
        return CGROUP_ERR;
    }
    int res = read_file(path, buf, sizeof(buf));
    if (res < 0) {
        debug("%s: could not read %s: %s\n", __func__, path, strerror(-res));
        return CGROUP_ERR;
    }
    return parse_cgroup_value(buf);
}

/* Look up `key` in the content of a flat-keyed cgroup file (memory.stat),
 * which has one "key value" pair per line.
 * Unlike a plain strstr() this only matches at the start of a line, so
 * looking up "anon" does not find "anon_thp", and looking up "inactive_file"
 * does not find v1's "total_inactive_file".
 * Returns the value, or CGROUP_ERR if the key is not present. */
static long long get_stat_entry(const char* key, const char* buf)
{
    size_t keylen = strlen(key);

    for (const char* line = buf; line != NULL && *line != 0;) {
        if (strncmp(line, key, keylen) == 0 && line[keylen] == ' ') {
            errno = 0;
            char* end = NULL;
            long long val = strtoll(line + keylen + 1, &end, 10);
            if (errno != 0 || end == line + keylen + 1) {
                return CGROUP_ERR;
            }
            return val;
        }
        line = strchr(line, '\n');
        if (line != NULL) {
            line++;
        }
    }
    return CGROUP_ERR;
}

/* Name of the file holding the memory limit, resp. the current usage. */
static const char* limit_file(void)
{
    return cg.v2 ? "memory.max" : "memory.limit_in_bytes";
}

static const char* usage_file(void)
{
    return cg.v2 ? "memory.current" : "memory.usage_in_bytes";
}

/* Read the memory limit of `dir`, in KiB.
 * Returns CGROUP_UNLIMITED when the cgroup is unconstrained and CGROUP_ERR
 * when the limit could not be read at all. */
static long long read_limit_kib(const char* dir)
{
    long long val = read_cgroup_value(dir, limit_file());
    if (val < 0 || val == CGROUP_UNLIMITED) {
        return val;
    }
    return val / 1024;
}

/* Find the path of `pid`'s cgroup inside the memory hierarchy by parsing
 * /proc/[pid]/cgroup. The v2 line looks like
 *     0::/kubepods.slice/kubepods-podXYZ.slice/cri-containerd-ABC.scope
 * and the v1 line we want carries the "memory" controller:
 *     3:memory:/user.slice/user-1000.slice/session-1.scope
 * Returns 0 on success and -errno on error. */
static int read_pid_cgroup(const char* pid, char* out, size_t outlen)
{
    char path[CGROUP_PATH_LEN] = { 0 };
    /* Kernels with many v1 controllers produce ~1 KiB here. */
    char buf[4096] = { 0 };

    if (!join_path(path, sizeof(path), procdir_path, "/", pid)) {
        return -ENAMETOOLONG;
    }
    char full[CGROUP_PATH_LEN] = { 0 };
    if (!join_path(full, sizeof(full), path, "/cgroup", "")) {
        return -ENAMETOOLONG;
    }
    int res = read_file(full, buf, sizeof(buf));
    if (res < 0) {
        return res;
    }

    for (char* line = buf; line != NULL && *line != 0;) {
        char* next = strchr(line, '\n');
        if (next != NULL) {
            *next = 0;
            next++;
        }
        /* hierarchy-ID:controller-list:cgroup-path */
        char* colon1 = strchr(line, ':');
        if (colon1 == NULL) {
            line = next;
            continue;
        }
        char* colon2 = strchr(colon1 + 1, ':');
        if (colon2 == NULL) {
            line = next;
            continue;
        }
        *colon2 = 0;
        const char* controllers = colon1 + 1;
        const char* cgroup_path = colon2 + 1;

        bool match = false;
        if (cg.v2) {
            /* The unified hierarchy has an empty controller list */
            match = (controllers[0] == 0);
        } else {
            /* The controller list is comma-separated ("cpu,cpuacct"), so we
             * look for "memory" as a whole element. A plain strstr() would
             * also accept the named hierarchy "name=memory". */
            const char* hit = strstr(controllers, "memory");
            const size_t n = strlen("memory");
            match = (hit != NULL && (hit == controllers || hit[-1] == ',')
                && (hit[n] == 0 || hit[n] == ','));
        }
        if (match) {
            snprintf(out, outlen, "%s", cgroup_path);
            return 0;
        }
        line = next;
    }
    return -ENOENT;
}

/* Locate the memory hierarchy and store it in cg.base / cg.v2.
 * Returns true if a memory cgroup hierarchy is mounted. */
static bool find_base(void)
{
    char path[CGROUP_PATH_LEN] = { 0 };

    /* A unified (v2) hierarchy is identified by cgroup.controllers in its
     * root. On "hybrid" systems the memory controller stays on v1, and
     * /sys/fs/cgroup itself is a tmpfs without that file. */
    if (!join_path(path, sizeof(path), cgroupdir_path, "/cgroup.controllers", "")) {
        return false;
    }
    if (access(path, R_OK) == 0) {
        cg.v2 = true;
        return join_path(cg.base, sizeof(cg.base), cgroupdir_path, "", "");
    }

    cg.v2 = false;
    if (!join_path(cg.base, sizeof(cg.base), cgroupdir_path, "/memory", "")) {
        return false;
    }
    if (read_limit_kib(cg.base) != CGROUP_ERR) {
        return true;
    }

    debug("%s: no memory cgroup hierarchy below %s\n", __func__, cgroupdir_path);
    return false;
}

/* Find the cgroup directory earlyoom lives in.
 * Returns true on success. */
static bool find_leaf(char* out, size_t outlen)
{
    char self[CGROUP_PATH_LEN] = { 0 };
    char path[CGROUP_PATH_LEN] = { 0 };

    int res = read_pid_cgroup("self", self, sizeof(self));
    if (res < 0) {
        debug("%s: could not read our own cgroup: %s\n", __func__, strerror(-res));
        /* Fall through: cg.base may still be the right directory. */
    }

    /* When we run in a cgroup namespace - the default for containers these
     * days - /sys/fs/cgroup is already the container's own cgroup and
     * /proc/self/cgroup says "/". Without a namespace, /proc/self/cgroup
     * gives the path we have to append. Try the deeper path first. */
    if (res == 0 && self[0] == '/' && self[1] != 0
        && join_path(path, sizeof(path), cg.base, self, "")) {
        if (read_limit_kib(path) != CGROUP_ERR) {
            return join_path(out, outlen, path, "", "");
        }
        debug("%s: %s is not readable, falling back to %s\n", __func__, path, cg.base);
    }
    if (read_limit_kib(cg.base) != CGROUP_ERR) {
        return join_path(out, outlen, cg.base, "", "");
    }
    return false;
}

/* Walk from our own cgroup up to the root of the hierarchy and remember the
 * one with the lowest memory limit - that is the one that will OOM-kill us
 * first. In Kubernetes this is normally the container's own cgroup, but a
 * container without a limit of its own can still be capped by its pod.
 *
 * `host_total_kib` is used to weed out limits that are not really limits:
 * a cgroup that may use more memory than the machine has does not constrain
 * us in any way, and we are better off watching /proc/meminfo.
 *
 * Returns true if a limit was found. */
static bool find_binding_dir(long long host_total_kib)
{
    char leaf[CGROUP_PATH_LEN] = { 0 };
    long long best_kib = CGROUP_UNLIMITED;
    size_t baselen = strlen(cg.base);

    if (!find_leaf(leaf, sizeof(leaf))) {
        debug("%s: could not find our cgroup below %s\n", __func__, cg.base);
        return false;
    }

    for (size_t len = strlen(leaf);; len--) {
        long long limit_kib = read_limit_kib(leaf);
        debug("%s: %s: limit %lld KiB\n", __func__, leaf, limit_kib);
        /* v1 stores "unlimited" as a huge number instead of "max", and a
         * limit above the size of the machine can never bite either. */
        if (limit_kib >= 0 && limit_kib < host_total_kib && limit_kib < best_kib
            && join_path(cg.dir, sizeof(cg.dir), leaf, "", "")) {
            best_kib = limit_kib;
        }
        if (len <= baselen) {
            break;
        }
        /* Strip the last path component and look at the parent cgroup. */
        while (len > baselen && leaf[len - 1] != '/') {
            len--;
        }
        leaf[--len] = 0;
    }
    return best_kib != CGROUP_UNLIMITED;
}

/* True if `path` has a ".." component.
 *
 * When the cgroup of a process lies outside of the cgroup namespace of the
 * reader, the kernel cannot name it with an absolute path and writes a
 * relative one instead: a pod that runs with hostPID sees its own cgroup as
 * "/" but the host's PID 1 as "/../../../../init.scope". A ".." is therefore
 * the kernel telling us "this is not below your cgroup". */
static bool has_dotdot(const char* path)
{
    for (const char* p = path; (p = strstr(p, "..")) != NULL; p += 2) {
        bool at_start = (p == path || p[-1] == '/');
        bool at_end = (p[2] == 0 || p[2] == '/');
        if (at_start && at_end) {
            return true;
        }
    }
    return false;
}

/* Is `path`, as it appears in /proc/[pid]/cgroup, at or below the cgroup
 * whose limit we picked? */
static bool below_our_cgroup(const char* path)
{
    /* Inside a cgroup namespace our own cgroup is "/", so every path starts
     * with it and the prefix test below would accept anything. The kernel
     * marks what is outside the namespace with "..". */
    if (has_dotdot(path)) {
        return false;
    }
    /* cg.dir always starts with cg.base, the rest is the cgroup path as it
     * appears in /proc/[pid]/cgroup. */
    const char* ours = cg.dir + strlen(cg.base);
    size_t len = strlen(ours);
    if (strncmp(path, ours, len) != 0 || (path[len] != 0 && path[len] != '/')) {
        return false;
    }
    return true;
}

/* Killing a process only frees memory in the cgroup that process belongs to,
 * so a limit is only worth watching if it covers the processes earlyoom would
 * actually kill. Compare the two directly: `pid` is the process
 * find_largest_process() picked, `rss_kib` is its size.
 *
 * The case this catches is an earlyoom that runs on a node with hostPID and
 * has a memory limit of its own. It sees the whole node in /proc but lives in
 * a small cgroup of its own, and watching that cgroup would mean waiting for
 * a limit that the processes it can kill never touch. The node's memory is
 * what we can actually do something about there.
 *
 * On an idle machine the largest process is arbitrary - every candidate is a
 * few hundred kiB - and tells us nothing. Only judge by a candidate that is
 * big enough to be worth killing in the first place.
 */
void cgroup_verify_victim(int pid, long long rss_kib)
{
    char pidstr[16] = { 0 };
    char victim[CGROUP_PATH_LEN] = { 0 };

    if (cg.state != CGROUP_ACTIVE || cgroup_forced) {
        return;
    }
    if (pid <= 0) {
        debug("%s: no victim to check against\n", __func__);
        return;
    }
    if (rss_kib < cg.limit_kib / 20) {
        debug("%s: pid %d is only %lld KiB, too small to tell\n", __func__, pid, rss_kib);
        return;
    }
    snprintf(pidstr, sizeof(pidstr), "%d", pid);
    int res = read_pid_cgroup(pidstr, victim, sizeof(victim));
    if (res < 0) {
        debug("%s: cannot read the cgroup of pid %d: %s\n", __func__, pid, strerror(-res));
        return;
    }
    if (below_our_cgroup(victim)) {
        debug("%s: pid %d is in %s, covered by our limit\n", __func__, pid, victim);
        return;
    }
    cg.state = CGROUP_INACTIVE;
    warn("the memory limit of %s does not cover the processes earlyoom would kill\n"
         "(pid %d lives in %s), ignoring it. Pass --cgroup to use it anyway,\n"
         "or --no-cgroup to silence this message.\n",
        cg.dir, pid, victim);
}

static void probe(long long host_total_kib)
{
    memset(cg.base, 0, sizeof(cg.base));
    memset(cg.dir, 0, sizeof(cg.dir));
    cg.limit_kib = 0;

    if (!find_base() || !find_binding_dir(host_total_kib)) {
        cg.state = CGROUP_INACTIVE;
        debug("%s: no cgroup memory limit in effect, using /proc/meminfo\n", __func__);
        return;
    }
    cg.state = CGROUP_ACTIVE;
    cg.limit_kib = read_limit_kib(cg.dir);
    debug("%s: using the cgroup v%d memory limit of %s\n", __func__, cg.v2 ? 2 : 1, cg.dir);
}

/* Overwrite the swap numbers in `m` with the ones of our cgroup.
 * Silently does nothing when the cgroup does not account swap separately -
 * the host-wide values from /proc/meminfo are the best guess then. */
static void cgroup_swap(meminfo_t* m)
{
    long long total = 0, used = 0;

    if (cg.v2) {
        total = read_cgroup_value(cg.dir, "memory.swap.max");
        used = read_cgroup_value(cg.dir, "memory.swap.current");
    } else {
        /* v1 has no separate swap counter, only the combined mem+swap one.
         * Requires swapaccount=1 on the kernel command line, so it is
         * usually absent. */
        long long memsw_limit = read_cgroup_value(cg.dir, "memory.memsw.limit_in_bytes");
        long long memsw_usage = read_cgroup_value(cg.dir, "memory.memsw.usage_in_bytes");
        long long mem_limit = read_cgroup_value(cg.dir, limit_file());
        long long mem_usage = read_cgroup_value(cg.dir, usage_file());
        if (memsw_limit < 0 || memsw_usage < 0 || mem_limit < 0 || mem_usage < 0
            || memsw_limit == CGROUP_UNLIMITED || mem_limit == CGROUP_UNLIMITED) {
            return;
        }
        total = memsw_limit - mem_limit;
        used = memsw_usage - mem_usage;
    }
    if (total < 0 || total == CGROUP_UNLIMITED || used < 0 || used == CGROUP_UNLIMITED) {
        return;
    }

    long long total_kib = total / 1024;
    long long used_kib = used / 1024;
    /* A cgroup may be allowed more swap than the machine actually has.
     * Docker and podman, for example, default memory.memsw.limit_in_bytes
     * to twice the memory limit even on a host without any swap at all,
     * and believing that would leave earlyoom waiting forever for swap
     * that can never fill up. */
    if (total_kib > m->SwapTotalKiB) {
        total_kib = m->SwapTotalKiB;
    }
    if (used_kib > total_kib) {
        used_kib = total_kib;
    }
    m->SwapTotalKiB = total_kib;
    m->SwapFreeKiB = total_kib - used_kib;
}

bool cgroup_meminfo(meminfo_t* m)
{
    if (cgroup_disabled) {
        return false;
    }
    if (cg.state == CGROUP_UNPROBED) {
        probe(m->MemTotalKiB);
    }
    if (cg.state != CGROUP_ACTIVE) {
        return false;
    }

    /* memory.stat is below 1 KiB on Linux 6.6, 8192 leaves plenty of room. */
    char buf[8192] = { 0 };
    char path[CGROUP_PATH_LEN] = { 0 };

    /* Re-read the limit every time: it can change under our feet, for
     * example when a Kubernetes pod is resized in place. */
    long long limit_kib = read_limit_kib(cg.dir);
    long long usage = read_cgroup_value(cg.dir, usage_file());
    int res = -ENAMETOOLONG;
    if (join_path(path, sizeof(path), cg.dir, "/memory.stat", "")) {
        res = read_file(path, buf, sizeof(buf));
    }

    if (limit_kib == CGROUP_ERR || limit_kib == CGROUP_UNLIMITED
        || limit_kib >= m->MemTotalKiB || usage < 0 || res < 0) {
        /* The cgroup went away (pod restart) or lost its limit. Probe again
         * on the next call, and use the host values in the meantime. */
        warn("cgroup %s no longer provides a usable memory limit, falling back to /proc/meminfo\n", cg.dir);
        cg.state = CGROUP_UNPROBED;
        return false;
    }

    long long inactive_file = get_stat_entry(cg.v2 ? "inactive_file" : "total_inactive_file", buf);
    long long anon = get_stat_entry(cg.v2 ? "anon" : "total_rss", buf);
    if (inactive_file < 0) {
        inactive_file = 0;
    }
    if (anon < 0) {
        anon = 0;
    }

    /* The page cache on the inactive file list is dropped instead of being
     * OOM-killed for, so it counts as available. This is the same
     * "working set" the kubelet and cadvisor report. */
    long long workingset = usage - inactive_file;
    if (workingset < 0) {
        workingset = 0;
    }
    long long avail_kib = limit_kib - workingset / 1024;
    if (avail_kib < 0) {
        avail_kib = 0;
    }

    m->MemTotalKiB = limit_kib;
    m->MemAvailableKiB = avail_kib;
    m->AnonPagesKiB = anon / 1024;
    cgroup_swap(m);
    return true;
}

const char* cgroup_dir(void)
{
    if (cg.state != CGROUP_ACTIVE) {
        return NULL;
    }
    return cg.dir;
}

void cgroup_reset(void)
{
    memset(&cg, 0, sizeof(cg));
}
