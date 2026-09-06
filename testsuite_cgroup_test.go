package earlyoom_testsuite

import (
	"fmt"
	"os"
	"testing"
)

// A machine with 16 GiB of RAM and no swap, as read from /proc/meminfo.
var hostMeminfo = meminfoValues{
	MemTotalKiB:     16 * 1024 * 1024,
	MemAvailableKiB: 12 * 1024 * 1024,
	AnonPagesKiB:    3 * 1024 * 1024,
}

const gib = 1024 * 1024 * 1024

// A Kubernetes pod running with a cgroup namespace: /proc/self/cgroup says
// "/" and the container's own cgroup is mounted at /sys/fs/cgroup.
func TestCgroupV2Namespaced(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		v2: true,
		files: map[string]string{
			"memory.max":     "2147483648\n", // 2 GiB
			"memory.current": "1073741824\n", // 1 GiB
			// 256 MiB of the usage is reclaimable page cache
			"memory.stat": "anon 536870912\nfile 536870912\ninactive_file 268435456\nanon_thp 0\nslab_reclaimable 4096\n",
		},
	})

	changed, m := cgroup_meminfo(hostMeminfo)
	if !changed {
		t.Fatal("cgroup limit was not picked up")
	}
	if m.MemTotalKiB != 2*1024*1024 {
		t.Errorf("MemTotalKiB = %d, want %d", m.MemTotalKiB, 2*1024*1024)
	}
	// available = 2 GiB - (1 GiB - 256 MiB) = 1.25 GiB
	if want := int64(1280 * 1024); m.MemAvailableKiB != want {
		t.Errorf("MemAvailableKiB = %d, want %d", m.MemAvailableKiB, want)
	}
	if want := int64(512 * 1024); m.AnonPagesKiB != want {
		t.Errorf("AnonPagesKiB = %d, want %d", m.AnonPagesKiB, want)
	}
}

// Without a cgroup namespace, /proc/self/cgroup carries the full path and we
// have to append it to the mount point.
func TestCgroupV2NestedPath(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		v2:   true,
		self: "/kubepods.slice/kubepods-podabc.slice/cri-containerd-def.scope",
		files: map[string]string{
			"kubepods.slice/kubepods-podabc.slice/cri-containerd-def.scope/memory.max":     "1073741824\n",
			"kubepods.slice/kubepods-podabc.slice/cri-containerd-def.scope/memory.current": "104857600\n",
			"kubepods.slice/kubepods-podabc.slice/cri-containerd-def.scope/memory.stat":    "anon 104857600\ninactive_file 0\n",
			// The pod above us is unlimited
			"kubepods.slice/kubepods-podabc.slice/memory.max": "max\n",
			"kubepods.slice/memory.max":                       "max\n",
			"memory.max":                                      "max\n",
		},
	})

	changed, m := cgroup_meminfo(hostMeminfo)
	if !changed {
		t.Fatal("cgroup limit was not picked up")
	}
	if m.MemTotalKiB != 1024*1024 {
		t.Errorf("MemTotalKiB = %d, want %d", m.MemTotalKiB, 1024*1024)
	}
	if want := int64(1024*1024 - 100*1024); m.MemAvailableKiB != want {
		t.Errorf("MemAvailableKiB = %d, want %d", m.MemAvailableKiB, want)
	}
}

// A container without a limit of its own is still capped by its pod, so we
// have to walk up the hierarchy.
func TestCgroupV2LimitOnParent(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		v2:   true,
		self: "/pod/ctr",
		files: map[string]string{
			"pod/ctr/memory.max":     "max\n",
			"pod/ctr/memory.current": "104857600\n",
			"pod/ctr/memory.stat":    "anon 104857600\ninactive_file 0\n",
			"pod/memory.max":         "536870912\n", // 512 MiB
			"pod/memory.current":     "209715200\n", // 200 MiB
			"pod/memory.stat":        "anon 209715200\ninactive_file 0\n",
			"memory.max":             "max\n",
		},
	})

	changed, m := cgroup_meminfo(hostMeminfo)
	if !changed {
		t.Fatal("cgroup limit was not picked up")
	}
	if got := cgroup_dir(); got[len(got)-4:] != "/pod" {
		t.Errorf("cgroup_dir() = %q, want it to end in /pod", got)
	}
	if m.MemTotalKiB != 512*1024 {
		t.Errorf("MemTotalKiB = %d, want %d", m.MemTotalKiB, 512*1024)
	}
	if want := int64(512*1024 - 200*1024); m.MemAvailableKiB != want {
		t.Errorf("MemAvailableKiB = %d, want %d", m.MemAvailableKiB, want)
	}
}

// The tightest limit wins, no matter at which level it sits.
func TestCgroupV2TightestLimitWins(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		v2:   true,
		self: "/pod/ctr",
		files: map[string]string{
			"pod/ctr/memory.max":     "2147483648\n", // 2 GiB
			"pod/ctr/memory.current": "104857600\n",
			"pod/ctr/memory.stat":    "anon 104857600\ninactive_file 0\n",
			"pod/memory.max":         "268435456\n", // 256 MiB - tighter
			"pod/memory.current":     "134217728\n",
			"pod/memory.stat":        "anon 134217728\ninactive_file 0\n",
			"memory.max":             "max\n",
		},
	})

	_, m := cgroup_meminfo(hostMeminfo)
	if m.MemTotalKiB != 256*1024 {
		t.Errorf("MemTotalKiB = %d, want %d", m.MemTotalKiB, 256*1024)
	}
}

func TestCgroupV2Swap(t *testing.T) {
	host := hostMeminfo
	host.SwapTotalKiB = 4 * 1024 * 1024
	host.SwapFreeKiB = 4 * 1024 * 1024

	mockCgroup(t, mockCgroupOpts{
		v2: true,
		files: map[string]string{
			"memory.max":          "1073741824\n",
			"memory.current":      "536870912\n",
			"memory.stat":         "anon 536870912\ninactive_file 0\n",
			"memory.swap.max":     "536870912\n", // 512 MiB
			"memory.swap.current": "134217728\n", // 128 MiB used
		},
	})

	_, m := cgroup_meminfo(host)
	if want := int64(512 * 1024); m.SwapTotalKiB != want {
		t.Errorf("SwapTotalKiB = %d, want %d", m.SwapTotalKiB, want)
	}
	if want := int64(384 * 1024); m.SwapFreeKiB != want {
		t.Errorf("SwapFreeKiB = %d, want %d", m.SwapFreeKiB, want)
	}
}

// Kubernetes disables swap for pods by default, which shows up as
// memory.swap.max = 0.
func TestCgroupV2SwapDisabled(t *testing.T) {
	host := hostMeminfo
	host.SwapTotalKiB = 4 * 1024 * 1024
	host.SwapFreeKiB = 4 * 1024 * 1024

	mockCgroup(t, mockCgroupOpts{
		v2: true,
		files: map[string]string{
			"memory.max":          "1073741824\n",
			"memory.current":      "536870912\n",
			"memory.stat":         "anon 536870912\ninactive_file 0\n",
			"memory.swap.max":     "0\n",
			"memory.swap.current": "0\n",
		},
	})

	_, m := cgroup_meminfo(host)
	if m.SwapTotalKiB != 0 || m.SwapFreeKiB != 0 {
		t.Errorf("swap = %d/%d, want 0/0", m.SwapFreeKiB, m.SwapTotalKiB)
	}
}

// An unconstrained cgroup must leave the host values alone.
func TestCgroupV2NoLimit(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		v2: true,
		files: map[string]string{
			"memory.max":     "max\n",
			"memory.current": "536870912\n",
			"memory.stat":    "anon 536870912\ninactive_file 0\n",
		},
	})

	changed, m := cgroup_meminfo(hostMeminfo)
	if changed {
		t.Error("an unlimited cgroup must not change anything")
	}
	if m != hostMeminfo {
		t.Errorf("meminfo was modified: %+v", m)
	}
	if cgroup_dir() != "" {
		t.Errorf("cgroup_dir() = %q, want empty", cgroup_dir())
	}
}

// A limit that is larger than the machine does not constrain us either.
func TestCgroupV2LimitAboveHostMemory(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		v2: true,
		files: map[string]string{
			"memory.max":     "68719476736\n", // 64 GiB on a 16 GiB machine
			"memory.current": "536870912\n",
			"memory.stat":    "anon 536870912\ninactive_file 0\n",
		},
	})

	if changed, _ := cgroup_meminfo(hostMeminfo); changed {
		t.Error("a limit above the size of the machine must be ignored")
	}
}

func TestCgroupV1(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		self: "/docker/abc",
		files: map[string]string{
			"docker/abc/memory.limit_in_bytes": "2147483648\n", // 2 GiB
			"docker/abc/memory.usage_in_bytes": "1073741824\n", // 1 GiB
			// The hierarchical "total_" values are the ones we want, and
			// looking up "inactive_file" must not match "total_inactive_file".
			"docker/abc/memory.stat": "cache 536870912\nrss 536870912\ninactive_file 1\n" +
				"total_cache 536870912\ntotal_rss 536870912\ntotal_inactive_file 268435456\n",
		},
	})

	changed, m := cgroup_meminfo(hostMeminfo)
	if !changed {
		t.Fatal("cgroup limit was not picked up")
	}
	if m.MemTotalKiB != 2*1024*1024 {
		t.Errorf("MemTotalKiB = %d, want %d", m.MemTotalKiB, 2*1024*1024)
	}
	if want := int64(1280 * 1024); m.MemAvailableKiB != want {
		t.Errorf("MemAvailableKiB = %d, want %d", m.MemAvailableKiB, want)
	}
	if want := int64(512 * 1024); m.AnonPagesKiB != want {
		t.Errorf("AnonPagesKiB = %d, want %d", m.AnonPagesKiB, want)
	}
}

// cgroup v1 spells "unlimited" as PAGE_COUNTER_MAX.
func TestCgroupV1Unlimited(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		files: map[string]string{
			"memory.limit_in_bytes": "9223372036854771712\n",
			"memory.usage_in_bytes": "1073741824\n",
			"memory.stat":           "total_rss 536870912\ntotal_inactive_file 0\n",
		},
	})

	if changed, _ := cgroup_meminfo(hostMeminfo); changed {
		t.Error("PAGE_COUNTER_MAX must be treated as unlimited")
	}
}

// Docker and podman set memory.memsw.limit_in_bytes to twice the memory
// limit by default, even on a host that has no swap at all. We must not
// invent swap that does not exist, otherwise earlyoom waits forever for it
// to fill up.
func TestCgroupV1MemswOnSwaplessHost(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		files: map[string]string{
			"memory.limit_in_bytes":       "536870912\n",  // 512 MiB
			"memory.memsw.limit_in_bytes": "1073741824\n", // 1 GiB
			"memory.usage_in_bytes":       "104857600\n",
			"memory.memsw.usage_in_bytes": "104857600\n",
			"memory.stat":                 "total_rss 104857600\ntotal_inactive_file 0\n",
		},
	})

	// hostMeminfo has no swap
	_, m := cgroup_meminfo(hostMeminfo)
	if m.SwapTotalKiB != 0 || m.SwapFreeKiB != 0 {
		t.Errorf("swap = %d/%d, want 0/0", m.SwapFreeKiB, m.SwapTotalKiB)
	}
}

// Without swapaccount=1 the memsw files do not exist and we keep the host's
// swap numbers.
func TestCgroupV1NoSwapAccounting(t *testing.T) {
	host := hostMeminfo
	host.SwapTotalKiB = 2 * 1024 * 1024
	host.SwapFreeKiB = 1024 * 1024

	mockCgroup(t, mockCgroupOpts{
		files: map[string]string{
			"memory.limit_in_bytes": "536870912\n",
			"memory.usage_in_bytes": "104857600\n",
			"memory.stat":           "total_rss 104857600\ntotal_inactive_file 0\n",
		},
	})

	_, m := cgroup_meminfo(host)
	if m.SwapTotalKiB != host.SwapTotalKiB || m.SwapFreeKiB != host.SwapFreeKiB {
		t.Errorf("swap = %d/%d, want %d/%d", m.SwapFreeKiB, m.SwapTotalKiB,
			host.SwapFreeKiB, host.SwapTotalKiB)
	}
}

// earlyoom on a node with hostPID sees the whole node in /proc but lives in a
// small cgroup of its own. The process it would kill is not covered by that
// limit, so the limit must be ignored. On GKE / Container-Optimized OS the
// kernel names such a cgroup with a path that escapes our cgroup namespace.
func TestCgroupVictimOutsideOurCgroup(t *testing.T) {
	files := map[string]string{
		"memory.max":     "134217728\n", // 128 MiB
		"memory.current": "10485760\n",
		"memory.stat":    "anon 10485760\ninactive_file 0\n",
	}
	// A big process on the node, in a cgroup outside ours
	procs := map[string]string{"77": "/../../../../system.slice/big.service"}

	mockCgroup(t, mockCgroupOpts{v2: true, files: files, procs: procs})
	if changed, _ := cgroup_meminfo(hostMeminfo); !changed {
		t.Fatal("the limit is picked up first")
	}
	cgroup_verify_victim(77, 4*1024*1024) // 4 GiB, clearly not ours
	if changed, _ := cgroup_meminfo(hostMeminfo); changed {
		t.Error("a limit that does not cover our victim must be dropped")
	}

	// --cgroup overrides the check
	mockCgroup(t, mockCgroupOpts{v2: true, files: files, procs: procs})
	cgroup_forced(true)
	cgroup_meminfo(hostMeminfo)
	cgroup_verify_victim(77, 4*1024*1024)
	if changed, _ := cgroup_meminfo(hostMeminfo); !changed {
		t.Error("--cgroup must override the victim check")
	}
}

// The victim is one of our own processes - the normal case in a pod.
func TestCgroupVictimInsideOurCgroup(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		v2: true,
		files: map[string]string{
			"memory.max":     "536870912\n",
			"memory.current": "104857600\n",
			"memory.stat":    "anon 104857600\ninactive_file 0\n",
		},
		procs: map[string]string{"42": "/"},
	})
	cgroup_meminfo(hostMeminfo)
	cgroup_verify_victim(42, 300*1024)
	if changed, _ := cgroup_meminfo(hostMeminfo); !changed {
		t.Error("a victim inside our cgroup must keep the limit")
	}
}

// With shareProcessNamespace the pod's pause process shows up in /proc, but
// that must not make us drop a limit that does cover the real workload.
// A candidate this small carries no signal, so the check has to stay out of
// the way. Regression test for a false negative seen on GKE.
func TestCgroupTinyVictimIsNoSignal(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		v2: true,
		files: map[string]string{
			"memory.max":     "402653184\n", // 384 MiB
			"memory.current": "10485760\n",
			"memory.stat":    "anon 10485760\ninactive_file 0\n",
		},
		// The pause container, one cgroup over
		procs: map[string]string{"1": "/../cri-containerd-pause.scope"},
	})
	cgroup_meminfo(hostMeminfo)
	// "sleep" on an idle pod: well under 5% of the 384 MiB limit
	cgroup_verify_victim(1, 700)
	if changed, _ := cgroup_meminfo(hostMeminfo); !changed {
		t.Error("an idle-sized candidate must not drop the limit")
	}
}

// ".." only counts as an escape marker when it is a whole path component.
func TestCgroupDotDotInName(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		v2: true,
		files: map[string]string{
			"memory.max":     "134217728\n",
			"memory.current": "10485760\n",
			"memory.stat":    "anon 10485760\ninactive_file 0\n",
		},
		procs: map[string]string{"9": "/my..cgroup"},
	})
	cgroup_meminfo(hostMeminfo)
	cgroup_verify_victim(9, 100*1024)
	if changed, _ := cgroup_meminfo(hostMeminfo); !changed {
		t.Error("a cgroup called \"my..cgroup\" is not an escaped path")
	}
}

// No victim at all, or one we cannot read: keep the limit rather than guess.
func TestCgroupVictimUnknown(t *testing.T) {
	files := map[string]string{
		"memory.max":     "134217728\n",
		"memory.current": "10485760\n",
		"memory.stat":    "anon 10485760\ninactive_file 0\n",
	}
	for _, pid := range []int{0, -1, 12345} {
		mockCgroup(t, mockCgroupOpts{v2: true, files: files})
		cgroup_meminfo(hostMeminfo)
		cgroup_verify_victim(pid, 100*1024)
		if changed, _ := cgroup_meminfo(hostMeminfo); !changed {
			t.Errorf("pid %d gives no signal, the limit must be kept", pid)
		}
	}
}

func TestCgroupDisabled(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		v2: true,
		files: map[string]string{
			"memory.max":     "1073741824\n",
			"memory.current": "536870912\n",
			"memory.stat":    "anon 536870912\ninactive_file 0\n",
		},
	})
	cgroup_disabled(true)

	if changed, _ := cgroup_meminfo(hostMeminfo); changed {
		t.Error("--no-cgroup must disable the cgroup lookup")
	}
}

// No cgroup filesystem at all, as in a chroot or a minimal container image.
func TestCgroupMissing(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{v2: true})
	cgroupdir_path("/nonexistent-cgroup-dir")

	if changed, _ := cgroup_meminfo(hostMeminfo); changed {
		t.Error("a missing cgroup filesystem must not change anything")
	}
}

// A cgroup that disappears under us - a pod restart, for example - must
// fall back to the host values instead of reporting stale numbers.
func TestCgroupVanishes(t *testing.T) {
	root := mockCgroup(t, mockCgroupOpts{
		v2: true,
		files: map[string]string{
			"memory.max":     "1073741824\n",
			"memory.current": "536870912\n",
			"memory.stat":    "anon 536870912\ninactive_file 0\n",
		},
	})
	if changed, _ := cgroup_meminfo(hostMeminfo); !changed {
		t.Fatal("cgroup limit was not picked up")
	}

	os.RemoveAll(root + "/cgroup")
	changed, m := cgroup_meminfo(hostMeminfo)
	if changed {
		t.Error("a vanished cgroup must fall back to /proc/meminfo")
	}
	if m != hostMeminfo {
		t.Errorf("meminfo was modified: %+v", m)
	}
}

// Usage above the limit (the moment before the kernel OOM killer steps in)
// must not produce a negative amount of available memory.
func TestCgroupUsageAboveLimit(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		v2: true,
		files: map[string]string{
			"memory.max":     "1073741824\n",
			"memory.current": "1181116006\n", // 1.1 GiB
			"memory.stat":    "anon 1181116006\ninactive_file 0\n",
		},
	})

	_, m := cgroup_meminfo(hostMeminfo)
	if m.MemAvailableKiB != 0 {
		t.Errorf("MemAvailableKiB = %d, want 0", m.MemAvailableKiB)
	}
}

// A systemd unit with MemoryMax= - the earlyoom.service shipped with this
// program sets 50M - puts earlyoom alone in a small cgroup. That limit
// governs nothing earlyoom could kill, so it must not be adopted at all:
// not with a warning, not silently. Running as a system daemon has to look
// exactly like it did before.
func TestCgroupSelfOnlyCgroupIsSkipped(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		v2:   true,
		self: "/system.slice/earlyoom.service",
		files: map[string]string{
			"system.slice/earlyoom.service/memory.max":     "52428800\n", // 50 MiB
			"system.slice/earlyoom.service/memory.current": "1048576\n",
			"system.slice/earlyoom.service/memory.stat":    "anon 1048576\ninactive_file 0\n",
			// Only our own pid lives here
			"system.slice/earlyoom.service/cgroup.procs": fmt.Sprintf("%d\n", os.Getpid()),
			"system.slice/memory.max":                    "max\n",
			"memory.max":                                 "max\n",
		},
	})

	changed, m := cgroup_meminfo(hostMeminfo)
	if changed {
		t.Error("a cgroup holding only earlyoom must not be adopted")
	}
	if m != hostMeminfo {
		t.Errorf("meminfo was modified: %+v", m)
	}
	if cgroup_dir() != "" {
		t.Errorf("cgroup_dir() = %q, want empty", cgroup_dir())
	}
}

// The same cgroup, but with a workload in it, is a real limit.
func TestCgroupWithOtherProcessesIsUsed(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		v2: true,
		files: map[string]string{
			"memory.max":     "52428800\n",
			"memory.current": "1048576\n",
			"memory.stat":    "anon 1048576\ninactive_file 0\n",
			"cgroup.procs":   fmt.Sprintf("%d\n%d\n", os.Getpid(), os.Getpid()+1),
		},
	})

	if changed, _ := cgroup_meminfo(hostMeminfo); !changed {
		t.Error("a cgroup with someone else in it is a real limit")
	}
}

// An unreadable cgroup.procs must not silently discard the limit.
func TestCgroupProcsUnreadable(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		v2: true,
		files: map[string]string{
			"memory.max":     "52428800\n",
			"memory.current": "1048576\n",
			"memory.stat":    "anon 1048576\ninactive_file 0\n",
			// no cgroup.procs at all
		},
	})

	if changed, _ := cgroup_meminfo(hostMeminfo); !changed {
		t.Error("when in doubt the limit must be kept")
	}
}

// Documents a real limitation rather than a behaviour: inside a cgroup
// namespace our own cgroup is the root of the mount, so a pod-level limit
// above it is not reachable and we fall back to the host values. Every other
// walk-up test uses the non-namespaced layout, where the parents are visible.
func TestCgroupNamespacedCannotReachPodLimit(t *testing.T) {
	mockCgroup(t, mockCgroupOpts{
		v2:   true,
		self: "/", // namespaced: /sys/fs/cgroup is our own cgroup
		files: map[string]string{
			"memory.max":     "max\n", // the container itself is unlimited
			"memory.current": "10485760\n",
			"memory.stat":    "anon 10485760\ninactive_file 0\n",
			"cgroup.procs":   fmt.Sprintf("%d\n%d\n", os.Getpid(), os.Getpid()+1),
		},
	})

	if changed, _ := cgroup_meminfo(hostMeminfo); changed {
		t.Error("nothing above the namespace root is visible, so no limit is found")
	}
}
