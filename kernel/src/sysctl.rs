//! Writable kernel tunables surfaced under /proc/sys (Linux sysctl).
//! Values live here so every consumer reads the live knob, not a const.

use core::sync::atomic::{AtomicU64, Ordering};

static PID_MAX: AtomicU64 = AtomicU64::new(32768);
static THREADS_MAX: AtomicU64 = AtomicU64::new(1024);
static YAMA_SCOPE: AtomicU64 = AtomicU64::new(0);
static FS_NR_OPEN: AtomicU64 = AtomicU64::new(1_048_576);
static FS_PIPE_MAX: AtomicU64 = AtomicU64::new(64 * 1024);
static INOTIFY_MAX_WATCHES: AtomicU64 = AtomicU64::new(128);
static FS_FILE_MAX: AtomicU64 = AtomicU64::new(1_048_576);
static PTY_MAX: AtomicU64 = AtomicU64::new(4096);
static VM_MAX_MAP_COUNT: AtomicU64 = AtomicU64::new(65530);
static SHMMAX: AtomicU64 = AtomicU64::new(32 * 1024 * 1024);
static SHMALL: AtomicU64 = AtomicU64::new(262144);
static SHMMNI: AtomicU64 = AtomicU64::new(4096);
static MQ_MSG_MAX: AtomicU64 = AtomicU64::new(10);
static MQ_MSGSIZE_MAX: AtomicU64 = AtomicU64::new(8192);
static MQ_QUEUES_MAX: AtomicU64 = AtomicU64::new(256);
static INOTIFY_MAX_QUEUED: AtomicU64 = AtomicU64::new(16384);
static EPOLL_MAX_WATCHES: AtomicU64 = AtomicU64::new(131072);
static UNPRIV_PORT_START: AtomicU64 = AtomicU64::new(1024);
static NGROUPS_MAX: AtomicU64 = AtomicU64::new(65536);
static OVERCOMMIT_MEMORY: AtomicU64 = AtomicU64::new(0);
static OVERCOMMIT_RATIO: AtomicU64 = AtomicU64::new(50);
static KPTR_RESTRICT: AtomicU64 = AtomicU64::new(0);
static PROTECTED_SYMLINKS: AtomicU64 = AtomicU64::new(1);
static LOCAL_PORT_LO: AtomicU64 = AtomicU64::new(49152);
static LOCAL_PORT_HI: AtomicU64 = AtomicU64::new(65535);
static UNPRIV_USERNS: AtomicU64 = AtomicU64::new(1);
static MMAP_MIN_ADDR: AtomicU64 = AtomicU64::new(0x10000);
static MIN_FREE_KB: AtomicU64 = AtomicU64::new(8192);
static PROTECTED_FIFOS: AtomicU64 = AtomicU64::new(1);
static PROTECTED_REGULAR: AtomicU64 = AtomicU64::new(0);
static UNIX_MAX_QLEN: AtomicU64 = AtomicU64::new(64);
static SOMAXCONN: AtomicU64 = AtomicU64::new(4096);
static USER_NS_MAX: AtomicU64 = AtomicU64::new(0);
static MNT_NS_MAX: AtomicU64 = AtomicU64::new(0);
static UTS_NS_MAX: AtomicU64 = AtomicU64::new(0);
static PID_NS_MAX: AtomicU64 = AtomicU64::new(0);
static IPC_NS_MAX: AtomicU64 = AtomicU64::new(0);
static TIME_NS_MAX: AtomicU64 = AtomicU64::new(0);
static TCP_WMEM_LO: AtomicU64 = AtomicU64::new(4096);
static TCP_WMEM_DEF: AtomicU64 = AtomicU64::new(16384);
static TCP_WMEM_MAX: AtomicU64 = AtomicU64::new(4194304);
static TCP_RMEM_LO: AtomicU64 = AtomicU64::new(4096);
static TCP_RMEM_DEF: AtomicU64 = AtomicU64::new(131072);
static TCP_RMEM_MAX: AtomicU64 = AtomicU64::new(6291456);
static NF_CT_MAX: AtomicU64 = AtomicU64::new(65536);
static ICMP_ECHO_IGNORE_BCAST: AtomicU64 = AtomicU64::new(1);
static IP_FORWARD: AtomicU64 = AtomicU64::new(0);
static KERNEL_SYSRQ: AtomicU64 = AtomicU64::new(1);
static DMESG_RESTRICT: AtomicU64 = AtomicU64::new(0);
static RANDOMIZE_VA: AtomicU64 = AtomicU64::new(2);

pub fn pid_max() -> u64 {
    PID_MAX.load(Ordering::Relaxed).clamp(1, 4_194_304)
}
pub fn threads_max() -> u64 {
    THREADS_MAX.load(Ordering::Relaxed).clamp(1, 1_048_576)
}
pub fn yama_scope() -> u64 {
    YAMA_SCOPE.load(Ordering::Relaxed)
}
pub fn fs_nr_open() -> u64 {
    FS_NR_OPEN.load(Ordering::Relaxed).clamp(1, 4_194_304)
}
pub fn fs_pipe_max() -> usize {
    (FS_PIPE_MAX.load(Ordering::Relaxed).clamp(4096, 1 << 20)) as usize
}
pub fn inotify_max_watches() -> u64 {
    INOTIFY_MAX_WATCHES.load(Ordering::Relaxed).clamp(1, 1 << 20)
}
pub fn fs_file_max() -> u64 {
    FS_FILE_MAX.load(Ordering::Relaxed).clamp(0, u64::MAX / 2)
}
pub fn pty_max() -> u64 {
    PTY_MAX.load(Ordering::Relaxed).clamp(0, 1 << 20)
}
pub fn vm_max_map_count() -> u64 {
    VM_MAX_MAP_COUNT.load(Ordering::Relaxed).clamp(1, u64::MAX / 2)
}
pub fn shmmax() -> u64 {
    SHMMAX.load(Ordering::Relaxed)
}
pub fn shmall() -> u64 {
    SHMALL.load(Ordering::Relaxed)
}
pub fn shmmni() -> u64 {
    SHMMNI.load(Ordering::Relaxed)
}
pub fn mq_msg_max() -> u64 {
    MQ_MSG_MAX.load(Ordering::Relaxed)
}
pub fn mq_msgsize_max() -> u64 {
    MQ_MSGSIZE_MAX.load(Ordering::Relaxed)
}
pub fn mq_queues_max() -> u64 {
    MQ_QUEUES_MAX.load(Ordering::Relaxed)
}
pub fn inotify_max_queued() -> usize {
    INOTIFY_MAX_QUEUED.load(Ordering::Relaxed) as usize
}
pub fn epoll_max_watches() -> u64 {
    EPOLL_MAX_WATCHES.load(Ordering::Relaxed)
}
pub fn unpriv_port_start() -> u64 {
    UNPRIV_PORT_START.load(Ordering::Relaxed).min(65535)
}
pub fn ngroups_max() -> u64 {
    NGROUPS_MAX.load(Ordering::Relaxed)
}
pub fn icmp_echo_ignore_bcast() -> u64 {
    ICMP_ECHO_IGNORE_BCAST.load(Ordering::Relaxed)
}
pub fn ip_forward() -> u64 {
    IP_FORWARD.load(Ordering::Relaxed)
}
pub fn kernel_sysrq() -> u64 {
    KERNEL_SYSRQ.load(Ordering::Relaxed)
}
pub fn dmesg_restrict() -> u64 {
    DMESG_RESTRICT.load(Ordering::Relaxed)
}
pub fn randomize_va_space() -> u64 {
    RANDOMIZE_VA.load(Ordering::Relaxed)
}
pub fn vm_overcommit_memory() -> u64 {
    OVERCOMMIT_MEMORY.load(Ordering::Relaxed)
}
pub fn vm_overcommit_ratio() -> u64 {
    OVERCOMMIT_RATIO.load(Ordering::Relaxed)
}
pub fn kptr_restrict() -> u64 {
    KPTR_RESTRICT.load(Ordering::Relaxed)
}
pub fn protected_symlinks() -> u64 {
    PROTECTED_SYMLINKS.load(Ordering::Relaxed)
}
pub fn local_port_range() -> (u64, u64) {
    (
        LOCAL_PORT_LO.load(Ordering::Relaxed),
        LOCAL_PORT_HI.load(Ordering::Relaxed),
    )
}
pub fn set_local_port_range(lo: u64, hi: u64) -> bool {
    if lo == 0 || hi == 0 || lo > hi || hi > 65535 {
        return false;
    }
    LOCAL_PORT_LO.store(lo, Ordering::Relaxed);
    LOCAL_PORT_HI.store(hi, Ordering::Relaxed);
    true
}
/// kernel.unprivileged_userns_clone (default 1): allow CLONE_NEWUSER
/// unshare() from tasks without CAP_SYS_ADMIN.
pub fn unpriv_userns_clone() -> u64 {
    UNPRIV_USERNS.load(Ordering::Relaxed)
}
/// vm.mmap_min_addr (default 64KiB): floor for MAP_FIXED placements —
/// CAP_SYS_RAWIO bypasses it like on Linux.
pub fn mmap_min_addr() -> u64 {
    MMAP_MIN_ADDR.load(Ordering::Relaxed)
}
/// vm.min_free_kbytes: userspace reservations must leave this much RAM
/// free — a zone-watermark style deny in the reserve path.
pub fn min_free_kbytes() -> u64 {
    MIN_FREE_KB.load(Ordering::Relaxed)
}
/// fs.protected_fifos: 1 = block O_WRONLY opens of foreign fifos in
/// sticky world-writable dirs, 2 = also gate read opens.
pub fn protected_fifos() -> u64 {
    PROTECTED_FIFOS.load(Ordering::Relaxed)
}
/// fs.protected_regular: O_CREAT open-for-write of an existing regular
/// file in a sticky+world-writable dir requires owning the file or the
/// dir (CAP_FOWNER exempts) — the regular-file arm of may_open.
pub fn protected_regular() -> u64 {
    PROTECTED_REGULAR.load(Ordering::Relaxed)
}
/// net.unix.max_dgram_qlen: per-mailbox datagram queue bound for
/// AF_UNIX SOCK_DGRAM — a full mailbox fails sends EAGAIN.
pub fn unix_max_dgram_qlen() -> u64 {
    UNIX_MAX_QLEN.load(Ordering::Relaxed)
}
/// net.core.somaxconn: per-listener accept-queue bound — the cap on
/// queued completed handshakes is min(listen backlog, this value).
pub fn somaxconn() -> u64 {
    SOMAXCONN.load(Ordering::Relaxed)
}
/// user.max_user_namespaces: per-creator userns cap (Linux ucounts).
/// 0 = unlimited, matching kernels that ship the knob unbounded.
pub fn max_user_namespaces() -> u64 {
    USER_NS_MAX.load(Ordering::Relaxed)
}
/// user.max_mnt_namespaces — per-creator live mount-ns cap (0 = no cap).
pub fn max_mnt_namespaces() -> u64 {
    MNT_NS_MAX.load(Ordering::Relaxed)
}
/// user.max_uts_namespaces — per-creator live uts-ns cap (0 = no cap).
pub fn max_uts_namespaces() -> u64 {
    UTS_NS_MAX.load(Ordering::Relaxed)
}
/// user.max_pid_namespaces — per-creator live pid-ns cap (0 = no cap).
pub fn max_pid_namespaces() -> u64 {
    PID_NS_MAX.load(Ordering::Relaxed)
}
/// user.max_ipc_namespaces — per-creator live ipc-ns cap (0 = no cap).
pub fn max_ipc_namespaces() -> u64 {
    IPC_NS_MAX.load(Ordering::Relaxed)
}
/// user.max_time_namespaces — per-creator live time-ns cap (0 = no cap).
pub fn max_time_namespaces() -> u64 {
    TIME_NS_MAX.load(Ordering::Relaxed)
}
/// net.ipv4.tcp_wmem — (min, default, max) send-buffer bytes; the max
/// bounds the real unacked-byte queue (Linux triple semantics).
pub fn tcp_wmem() -> (u64, u64, u64) {
    (
        TCP_WMEM_LO.load(Ordering::Relaxed),
        TCP_WMEM_DEF.load(Ordering::Relaxed),
        TCP_WMEM_MAX.load(Ordering::Relaxed),
    )
}
/// Write a tcp_wmem triple (1-3 values; missing slots keep the stored
/// value). Rejects a non-ordered triple like the kernel does.
pub fn set_tcp_wmem(lo: u64, def: u64, max: u64) -> bool {
    if !(lo <= def && def <= max && max <= (1 << 24)) {
        return false;
    }
    TCP_WMEM_LO.store(lo, Ordering::Relaxed);
    TCP_WMEM_DEF.store(def, Ordering::Relaxed);
    TCP_WMEM_MAX.store(max, Ordering::Relaxed);
    true
}
static RP_FILTER: AtomicU64 = AtomicU64::new(0);
static LOG_MARTIANS: AtomicU64 = AtomicU64::new(0);
static IP_NONLOCAL_BIND: AtomicU64 = AtomicU64::new(0);
static TCP_SYN_RETRIES: AtomicU64 = AtomicU64::new(6);
static TCP_FIN_TIMEOUT: AtomicU64 = AtomicU64::new(2);
static TCP_MAX_TW_BUCKETS: AtomicU64 = AtomicU64::new(4096);
static KA_TIME: AtomicU64 = AtomicU64::new(15);
static KA_INTVL: AtomicU64 = AtomicU64::new(1);
static KA_PROBES: AtomicU64 = AtomicU64::new(9);
static TCP_RETRIES1: AtomicU64 = AtomicU64::new(3);
static TCP_RETRIES2: AtomicU64 = AtomicU64::new(15);
static TCP_MAX_SYN_BACKLOG: AtomicU64 = AtomicU64::new(128);
static TCP_ABORT_ON_OVERFLOW: AtomicU64 = AtomicU64::new(0);
static ICMP_RATELIMIT: AtomicU64 = AtomicU64::new(1000);
static ICMP_RATEMASK: AtomicU64 = AtomicU64::new(0x1818);
static ICMP_MSGS_PER_SEC: AtomicU64 = AtomicU64::new(1000);
static ICMP_MSGS_BURST: AtomicU64 = AtomicU64::new(50);
static NEIGH_STALE_MS: AtomicU64 = AtomicU64::new(60_000);
static NEIGH_THRESH3: AtomicU64 = AtomicU64::new(1024);
static NEIGH_RETRANS_MS: AtomicU64 = AtomicU64::new(1000);
static NEIGH_MCAST_SOLICIT: AtomicU64 = AtomicU64::new(3);

/// net.ipv4.tcp_syn_retries — SYN re-send cap during connect()
/// (Linux default 6); the connect loop gives up ETIMEDOUT after
/// this many unanswered SYNs.
pub fn tcp_syn_retries() -> u64 {
    TCP_SYN_RETRIES.load(Ordering::Relaxed)
}
/// net.ipv4.tcp_fin_timeout — TIME_WAIT linger, seconds.
pub fn tcp_fin_timeout() -> u64 {
    TCP_FIN_TIMEOUT.load(Ordering::Relaxed)
}
/// net.ipv4.tcp_max_tw_buckets — cap on retained TIME_WAIT entries;
/// the oldest is destroyed when the table would overflow (Linux's
/// "time wait bucket table overflow" behavior).
pub fn tcp_max_tw_buckets() -> u64 {
    TCP_MAX_TW_BUCKETS.load(Ordering::Relaxed)
}
/// net.ipv4.tcp_keepalive_time — idle seconds before the first probe.
pub fn tcp_keepalive_time() -> u64 {
    KA_TIME.load(Ordering::Relaxed)
}
/// net.ipv4.tcp_keepalive_intvl — seconds between probes.
pub fn tcp_keepalive_intvl() -> u64 {
    KA_INTVL.load(Ordering::Relaxed)
}
/// net.ipv4.tcp_keepalive_probes — unanswered probes before the conn
/// is declared dead (ECONNRESET on read).
pub fn tcp_keepalive_probes() -> u64 {
    KA_PROBES.load(Ordering::Relaxed)
}
/// net.ipv4.tcp_retries1 — retransmit count on the oldest unacked
/// segment that marks a conn as struggling (klog notice; the Linux
/// "blackhole detection" threshold).
pub fn tcp_retries1() -> u64 {
    TCP_RETRIES1.load(Ordering::Relaxed)
}
/// net.ipv4.tcp_retries2 — give-up bound: once the retransmit count
/// of the oldest unacked segment passes this the conn is dead
/// (ECONNRESET on read). Linux default 15 (~15-30min there; our RTO
/// floor keeps it seconds).
pub fn tcp_retries2() -> u64 {
    TCP_RETRIES2.load(Ordering::Relaxed)
}
/// net.ipv4.tcp_max_syn_backlog — bound on half-open (SynRecv)
/// conns; a SYN past the cap is dropped so the queue can't fill.
pub fn tcp_max_syn_backlog() -> u64 {
    TCP_MAX_SYN_BACKLOG.load(Ordering::Relaxed)
}
/// net.ipv4.tcp_abort_on_overflow — 0 (Linux default): a full
/// accept queue silently drops the completing handshake ACK (the
/// peer's retransmit retries when a slot frees); 1: refuse with RST.
pub fn tcp_abort_on_overflow() -> u64 {
    TCP_ABORT_ON_OVERFLOW.load(Ordering::Relaxed)
}
/// net.ipv4.icmp_ratelimit — minimum ms between locally-generated
/// ICMP errors of the same type (Linux default 1000).
pub fn icmp_ratelimit() -> u64 {
    ICMP_RATELIMIT.load(Ordering::Relaxed)
}
/// net.ipv4.icmp_ratemask — bitmask of ICMP types the ratelimit
/// applies to (Linux default 0x1818: dest-unreach/src-quench/
/// time-exceeded/param-problem).
pub fn icmp_ratemask() -> u64 {
    ICMP_RATEMASK.load(Ordering::Relaxed)
}
/// net.ipv4.icmp_msgs_per_sec — global token-bucket refill rate on
/// ALL locally-generated ICMP errors.
pub fn icmp_msgs_per_sec() -> u64 {
    ICMP_MSGS_PER_SEC.load(Ordering::Relaxed)
}
/// net.ipv4.icmp_msgs_burst — token-bucket depth (Linux default 50).
pub fn icmp_msgs_burst() -> u64 {
    ICMP_MSGS_BURST.load(Ordering::Relaxed)
}
/// net.ipv4.neigh.default.gc_stale_time — ms a learned neighbour
/// entry stays REACHABLE before it ages to STALE (Linux default 60s).
pub fn neigh_stale_ms() -> u64 {
    NEIGH_STALE_MS.load(Ordering::Relaxed)
}
/// net.ipv4.neigh.default.gc_thresh3 — hard cap on dynamic neighbour
/// entries; a new ARP-learned entry past the cap is refused (Linux
/// default 1024).
pub fn neigh_thresh3() -> u64 {
    NEIGH_THRESH3.load(Ordering::Relaxed)
}
/// net.ipv4.neigh.default.retrans_time_ms — interval between ARP
/// probes while a resolve waits for an answer (Linux default 1000ms).
pub fn neigh_retrans_ms() -> u64 {
    NEIGH_RETRANS_MS.load(Ordering::Relaxed)
}
/// net.ipv4.neigh.default.mcast_solicit — total broadcast ARP probes
/// a resolve sends before giving up on retransmits (Linux default 3).
pub fn neigh_mcast_solicit() -> u64 {
    NEIGH_MCAST_SOLICIT.load(Ordering::Relaxed)
}

/// net.ipv4.conf.all.rp_filter — 0 off, 1 strict, 2 loose. Wire frames
/// whose source is martian (127/8, multicast-class, our own addr, or —
/// strict only — unrouteable back out eth0) are dropped at ingress.
pub fn rp_filter() -> u64 {
    RP_FILTER.load(Ordering::Relaxed)
}
pub fn set_rp_filter(v: u64) -> bool {
    if v > 2 {
        return false;
    }
    RP_FILTER.store(v, Ordering::Relaxed);
    true
}
/// net.ipv4.conf.all.log_martians — log each martian drop to klog.
pub fn log_martians() -> u64 {
    LOG_MARTIANS.load(Ordering::Relaxed)
}
pub fn set_log_martians(v: u64) -> bool {
    LOG_MARTIANS.store(v & 1, Ordering::Relaxed);
    true
}
/// net.ipv4.ip_nonlocal_bind — bind()/connect source addresses that
/// aren't ours no longer fail EADDRNOTAVAIL when set.
pub fn ip_nonlocal_bind() -> u64 {
    IP_NONLOCAL_BIND.load(Ordering::Relaxed)
}
pub fn set_ip_nonlocal_bind(v: u64) -> bool {
    IP_NONLOCAL_BIND.store(v & 1, Ordering::Relaxed);
    true
}

/// net.ipv4.tcp_rmem: [2] is the real byte ceiling backing rx_win —
/// the advertised receive window = rmem_max - queued bytes, and tcp_feed
/// drops data past the cap (real overflow behavior).
pub fn tcp_rmem() -> (u64, u64, u64) {
    (
        TCP_RMEM_LO.load(Ordering::Relaxed),
        TCP_RMEM_DEF.load(Ordering::Relaxed),
        TCP_RMEM_MAX.load(Ordering::Relaxed),
    )
}
/// Write a tcp_rmem triple (1-3 values). Rejects non-ordered triples.
pub fn set_tcp_rmem(lo: u64, def: u64, max: u64) -> bool {
    if !(lo <= def && def <= max && max <= (1 << 26)) {
        return false;
    }
    TCP_RMEM_LO.store(lo, Ordering::Relaxed);
    TCP_RMEM_DEF.store(def, Ordering::Relaxed);
    TCP_RMEM_MAX.store(max, Ordering::Relaxed);
    true
}
/// net.netfilter.nf_conntrack_max — real cap on the conntrack table.
pub fn nf_conntrack_max() -> u64 {
    NF_CT_MAX.load(Ordering::Relaxed)
}

/// sysctl name under /proc/sys → current value, or None when unknown.
/// Names are given relative, e.g. "kernel/pid_max", "fs/nr_open".
/// file-nr/pty-nr are computed live like the Linux file-table stats.
pub fn get(name: &str) -> Option<u64> {
    Some(match name {
        "kernel/pid_max" => PID_MAX.load(Ordering::Relaxed),
        "kernel/threads-max" => THREADS_MAX.load(Ordering::Relaxed),
        "kernel/yama/ptrace_scope" => YAMA_SCOPE.load(Ordering::Relaxed),
        "kernel/pty/max" => PTY_MAX.load(Ordering::Relaxed),
        "kernel/pty/nr" => crate::pty::count(),
        "fs/nr_open" => FS_NR_OPEN.load(Ordering::Relaxed),
        "fs/pipe-max-size" => FS_PIPE_MAX.load(Ordering::Relaxed),
        "fs/inotify/max_user_watches" => INOTIFY_MAX_WATCHES.load(Ordering::Relaxed),
        "fs/file-max" => FS_FILE_MAX.load(Ordering::Relaxed),
        "fs/file-nr" => crate::task::live_fd_count(),
        "vm/max_map_count" => VM_MAX_MAP_COUNT.load(Ordering::Relaxed),
        "kernel/shmmax" => SHMMAX.load(Ordering::Relaxed),
        "kernel/shmall" => SHMALL.load(Ordering::Relaxed),
        "kernel/shmmni" => SHMMNI.load(Ordering::Relaxed),
        "kernel/ngroups_max" => NGROUPS_MAX.load(Ordering::Relaxed),
        "fs/mqueue/msg_max" => MQ_MSG_MAX.load(Ordering::Relaxed),
        "fs/mqueue/msgsize_max" => MQ_MSGSIZE_MAX.load(Ordering::Relaxed),
        "fs/mqueue/queues_max" => MQ_QUEUES_MAX.load(Ordering::Relaxed),
        "fs/inotify/max_queued_events" => INOTIFY_MAX_QUEUED.load(Ordering::Relaxed),
        "fs/epoll/max_user_watches" => EPOLL_MAX_WATCHES.load(Ordering::Relaxed),
        "net/ipv4/ip_unprivileged_port_start" => {
            UNPRIV_PORT_START.load(Ordering::Relaxed).min(65535)
        }
        "net/ipv4/icmp_echo_ignore_broadcasts" => ICMP_ECHO_IGNORE_BCAST.load(Ordering::Relaxed),
        "net/ipv4/ip_forward" => IP_FORWARD.load(Ordering::Relaxed),
        "kernel/sysrq" => KERNEL_SYSRQ.load(Ordering::Relaxed),
        "kernel/dmesg_restrict" => DMESG_RESTRICT.load(Ordering::Relaxed),
        "kernel/randomize_va_space" => RANDOMIZE_VA.load(Ordering::Relaxed),
        "vm/overcommit_memory" => OVERCOMMIT_MEMORY.load(Ordering::Relaxed),
        "vm/overcommit_ratio" => OVERCOMMIT_RATIO.load(Ordering::Relaxed),
        "kernel/kptr_restrict" => KPTR_RESTRICT.load(Ordering::Relaxed),
        "fs/protected_symlinks" => PROTECTED_SYMLINKS.load(Ordering::Relaxed),

            "kernel/unprivileged_userns_clone" => UNPRIV_USERNS.load(Ordering::Relaxed),
        "vm/mmap_min_addr" => MMAP_MIN_ADDR.load(Ordering::Relaxed),
        "vm/min_free_kbytes" => MIN_FREE_KB.load(Ordering::Relaxed),
        "fs/protected_fifos" => PROTECTED_FIFOS.load(Ordering::Relaxed),
        "fs/protected_regular" => PROTECTED_REGULAR.load(Ordering::Relaxed),
        "net/unix/max_dgram_qlen" => UNIX_MAX_QLEN.load(Ordering::Relaxed),
        "net/core/somaxconn" => SOMAXCONN.load(Ordering::Relaxed),
        "user/max_user_namespaces" => USER_NS_MAX.load(Ordering::Relaxed),
        "user/max_mnt_namespaces" => MNT_NS_MAX.load(Ordering::Relaxed),
        "user/max_uts_namespaces" => UTS_NS_MAX.load(Ordering::Relaxed),
        "user/max_pid_namespaces" => PID_NS_MAX.load(Ordering::Relaxed),
        "user/max_ipc_namespaces" => IPC_NS_MAX.load(Ordering::Relaxed),
        "user/max_time_namespaces" => TIME_NS_MAX.load(Ordering::Relaxed),
        "net/netfilter/nf_conntrack_max" => NF_CT_MAX.load(Ordering::Relaxed),
        "net/ipv4/conf/all/rp_filter" => RP_FILTER.load(Ordering::Relaxed),
        "net/ipv4/conf/all/log_martians" => LOG_MARTIANS.load(Ordering::Relaxed),
        "net/ipv4/ip_nonlocal_bind" => IP_NONLOCAL_BIND.load(Ordering::Relaxed),
        "net/ipv4/tcp_syn_retries" => TCP_SYN_RETRIES.load(Ordering::Relaxed),
        "net/ipv4/tcp_fin_timeout" => TCP_FIN_TIMEOUT.load(Ordering::Relaxed),
        "net/ipv4/tcp_max_tw_buckets" => TCP_MAX_TW_BUCKETS.load(Ordering::Relaxed),
        "net/ipv4/tcp_keepalive_time" => KA_TIME.load(Ordering::Relaxed),
        "net/ipv4/tcp_keepalive_intvl" => KA_INTVL.load(Ordering::Relaxed),
        "net/ipv4/tcp_keepalive_probes" => KA_PROBES.load(Ordering::Relaxed),
        "net/ipv4/tcp_retries1" => TCP_RETRIES1.load(Ordering::Relaxed),
        "net/ipv4/tcp_retries2" => TCP_RETRIES2.load(Ordering::Relaxed),
        "net/ipv4/tcp_max_syn_backlog" => TCP_MAX_SYN_BACKLOG.load(Ordering::Relaxed),
        "net/ipv4/tcp_abort_on_overflow" => TCP_ABORT_ON_OVERFLOW.load(Ordering::Relaxed),
        "net/ipv4/icmp_ratelimit" => ICMP_RATELIMIT.load(Ordering::Relaxed),
        "net/ipv4/icmp_ratemask" => ICMP_RATEMASK.load(Ordering::Relaxed),
        "net/ipv4/icmp_msgs_per_sec" => ICMP_MSGS_PER_SEC.load(Ordering::Relaxed),
        "net/ipv4/icmp_msgs_burst" => ICMP_MSGS_BURST.load(Ordering::Relaxed),
        "net/ipv4/neigh/default/gc_stale_time" => NEIGH_STALE_MS.load(Ordering::Relaxed),
        "net/ipv4/neigh/default/gc_thresh3" => NEIGH_THRESH3.load(Ordering::Relaxed),
        "net/ipv4/neigh/default/retrans_time_ms" => NEIGH_RETRANS_MS.load(Ordering::Relaxed),
        "net/ipv4/neigh/default/mcast_solicit" => NEIGH_MCAST_SOLICIT.load(Ordering::Relaxed),

        _ => return None,
    })
}

/// Write a sysctl value — Linux rejects out-of-range/non-numeric input.
pub fn set(name: &str, v: u64) -> bool {
    match name {
        "kernel/pid_max" if (301..=4_194_304).contains(&v) => PID_MAX.store(v, Ordering::Relaxed),
        "kernel/threads-max" if v >= 1 => THREADS_MAX.store(v, Ordering::Relaxed),
        "kernel/yama/ptrace_scope" if v <= 3 => YAMA_SCOPE.store(v, Ordering::Relaxed),
        "kernel/pty/max" if v <= 1 << 20 => PTY_MAX.store(v, Ordering::Relaxed),
        "fs/nr_open" if (1..=4_194_304).contains(&v) => FS_NR_OPEN.store(v, Ordering::Relaxed),
        "fs/pipe-max-size" if (4096..=1 << 20).contains(&v) => FS_PIPE_MAX.store(v, Ordering::Relaxed),
        "fs/inotify/max_user_watches" if v > 0 => INOTIFY_MAX_WATCHES.store(v, Ordering::Relaxed),
        "fs/file-max" if v <= 1 << 30 => FS_FILE_MAX.store(v, Ordering::Relaxed),
        "vm/max_map_count" if v > 0 => VM_MAX_MAP_COUNT.store(v, Ordering::Relaxed),
        "kernel/shmmax" if v <= 1 << 40 => SHMMAX.store(v, Ordering::Relaxed),
        "kernel/shmall" if v <= 1 << 40 => SHMALL.store(v, Ordering::Relaxed),
        "kernel/shmmni" if v <= 1 << 20 => SHMMNI.store(v, Ordering::Relaxed),
        "kernel/ngroups_max" if v <= 1 << 20 => NGROUPS_MAX.store(v, Ordering::Relaxed),
        "fs/mqueue/msg_max" if (1..=1 << 16).contains(&v) => {
            MQ_MSG_MAX.store(v, Ordering::Relaxed)
        }
        "fs/mqueue/msgsize_max" if (1..=1 << 24).contains(&v) => {
            MQ_MSGSIZE_MAX.store(v, Ordering::Relaxed)
        }
        "fs/mqueue/queues_max" if v <= 1 << 16 => MQ_QUEUES_MAX.store(v, Ordering::Relaxed),
        "fs/inotify/max_queued_events" if v > 0 => {
            INOTIFY_MAX_QUEUED.store(v, Ordering::Relaxed)
        }
        "fs/epoll/max_user_watches" if v > 0 => {
            EPOLL_MAX_WATCHES.store(v, Ordering::Relaxed)
        }
        "net/ipv4/ip_unprivileged_port_start" if v <= 65535 => {
            UNPRIV_PORT_START.store(v, Ordering::Relaxed)
        }
        "net/ipv4/icmp_echo_ignore_broadcasts" if v <= 1 => {
            ICMP_ECHO_IGNORE_BCAST.store(v, Ordering::Relaxed)
        }
        "net/ipv4/ip_forward" if v <= 1 => IP_FORWARD.store(v, Ordering::Relaxed),
        "kernel/sysrq" if v <= 1 << 16 => KERNEL_SYSRQ.store(v, Ordering::Relaxed),
        "kernel/dmesg_restrict" if v <= 1 => DMESG_RESTRICT.store(v, Ordering::Relaxed),
        "kernel/randomize_va_space" if v <= 2 => RANDOMIZE_VA.store(v, Ordering::Relaxed),
        "vm/overcommit_memory" if v <= 2 => OVERCOMMIT_MEMORY.store(v, Ordering::Relaxed),
        "vm/overcommit_ratio" if v <= 100 => OVERCOMMIT_RATIO.store(v, Ordering::Relaxed),
        "kernel/kptr_restrict" if v <= 2 => KPTR_RESTRICT.store(v, Ordering::Relaxed),
        "fs/protected_symlinks" if v <= 1 => PROTECTED_SYMLINKS.store(v, Ordering::Relaxed),
        "kernel/unprivileged_userns_clone" if v <= 1 => {
            UNPRIV_USERNS.store(v, Ordering::Relaxed)
        }
        "vm/mmap_min_addr" if v <= 0x7e00_0000 => {
            MMAP_MIN_ADDR.store(v, Ordering::Relaxed)
        }
        "vm/min_free_kbytes" if v <= 4_194_304 => MIN_FREE_KB.store(v, Ordering::Relaxed),
        "fs/protected_fifos" if v <= 2 => PROTECTED_FIFOS.store(v, Ordering::Relaxed),
        "fs/protected_regular" if v <= 1 => {
            PROTECTED_REGULAR.store(v, Ordering::Relaxed)
        }
        "net/unix/max_dgram_qlen" if (1..=1024).contains(&v) => {
            UNIX_MAX_QLEN.store(v, Ordering::Relaxed)
        }
        "net/core/somaxconn" if (1..=65535).contains(&v) => {
            SOMAXCONN.store(v, Ordering::Relaxed)
        }
        "user/max_user_namespaces" if v <= 65535 => {
            USER_NS_MAX.store(v, Ordering::Relaxed)
        }
        "user/max_mnt_namespaces" if v <= 65535 => {
            MNT_NS_MAX.store(v, Ordering::Relaxed)
        }
        "user/max_uts_namespaces" if v <= 65535 => {
            UTS_NS_MAX.store(v, Ordering::Relaxed)
        }
        "user/max_pid_namespaces" if v <= 65535 => {
            PID_NS_MAX.store(v, Ordering::Relaxed)
        }
        "user/max_ipc_namespaces" if v <= 65535 => {
            IPC_NS_MAX.store(v, Ordering::Relaxed)
        }
        "user/max_time_namespaces" if v <= 65535 => {
            TIME_NS_MAX.store(v, Ordering::Relaxed)
        }
        "net/netfilter/nf_conntrack_max" if (1..=4194304).contains(&v) => {
            NF_CT_MAX.store(v, Ordering::Relaxed)
        }
        "net/ipv4/conf/all/rp_filter" if v <= 2 => {
            RP_FILTER.store(v, Ordering::Relaxed)
        }
        "net/ipv4/conf/all/log_martians" if v <= 1 => {
            LOG_MARTIANS.store(v, Ordering::Relaxed)
        }
        "net/ipv4/ip_nonlocal_bind" if v <= 1 => {
            IP_NONLOCAL_BIND.store(v, Ordering::Relaxed)
        }
        "net/ipv4/tcp_syn_retries" if v <= 127 => {
            TCP_SYN_RETRIES.store(v, Ordering::Relaxed)
        }
        "net/ipv4/tcp_fin_timeout" if v <= 3600 => {
            TCP_FIN_TIMEOUT.store(v, Ordering::Relaxed)
        }
        "net/ipv4/tcp_max_tw_buckets" if v <= (1 << 22) => {
            TCP_MAX_TW_BUCKETS.store(v, Ordering::Relaxed)
        }
        "net/ipv4/tcp_keepalive_time" if v <= 32767 => {
            KA_TIME.store(v.max(1), Ordering::Relaxed)
        }
        "net/ipv4/tcp_keepalive_intvl" if v <= 32767 => {
            KA_INTVL.store(v.max(1), Ordering::Relaxed)
        }
        "net/ipv4/tcp_keepalive_probes" if v <= 127 => {
            KA_PROBES.store(v, Ordering::Relaxed)
        }
        "net/ipv4/tcp_retries1" if v <= 255 => {
            TCP_RETRIES1.store(v, Ordering::Relaxed)
        }
        "net/ipv4/tcp_retries2" if v <= 255 => {
            TCP_RETRIES2.store(v, Ordering::Relaxed)
        }
        "net/ipv4/tcp_max_syn_backlog" if v <= (1 << 22) => {
            TCP_MAX_SYN_BACKLOG.store(v, Ordering::Relaxed)
        }
        "net/ipv4/tcp_abort_on_overflow" if v <= 1 => {
            TCP_ABORT_ON_OVERFLOW.store(v, Ordering::Relaxed)
        }
        "net/ipv4/icmp_ratelimit" if v <= 3_600_000 => {
            ICMP_RATELIMIT.store(v, Ordering::Relaxed)
        }
        "net/ipv4/icmp_ratemask" if v <= 0xFFFF_FFFF => {
            ICMP_RATEMASK.store(v, Ordering::Relaxed)
        }
        "net/ipv4/icmp_msgs_per_sec" if v <= 1_000_000 => {
            ICMP_MSGS_PER_SEC.store(v, Ordering::Relaxed)
        }
        "net/ipv4/icmp_msgs_burst" if v <= 1_000_000 => {
            ICMP_MSGS_BURST.store(v, Ordering::Relaxed)
        }
        "net/ipv4/neigh/default/gc_stale_time" if v <= 3_600_000 => {
            NEIGH_STALE_MS.store(v, Ordering::Relaxed)
        }
        "net/ipv4/neigh/default/gc_thresh3" if v <= 1 << 22 => {
            NEIGH_THRESH3.store(v, Ordering::Relaxed)
        }
        "net/ipv4/neigh/default/retrans_time_ms" if v <= 60_000 => {
            NEIGH_RETRANS_MS.store(v, Ordering::Relaxed)
        }
        "net/ipv4/neigh/default/mcast_solicit" if v <= 255 => {
            NEIGH_MCAST_SOLICIT.store(v, Ordering::Relaxed)
        }

        _ => return false,
    }
    true
}
