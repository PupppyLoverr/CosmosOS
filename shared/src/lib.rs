//! CosmosOS shared ABI: syscall numbers, kernel<->userspace data types,
//! and the window-server wire protocol. Used by both the kernel and `ustd`.
#![no_std]
pub mod font16;

// ---------------------------------------------------------------------------
// Syscall numbers (int 0x80: nr=rax, args rdi,rsi,rdx,r8,r9; ret rax)
// ---------------------------------------------------------------------------
pub const SYS_EXIT: u64 = 0;
pub const SYS_YIELD: u64 = 1;
pub const SYS_SPAWN: u64 = 2; // (path_ptr,path_len,arg_ptr,arg_len) -> pid | !0
pub const SYS_SLEEP_MS: u64 = 3; // (ms)
pub const SYS_MMAP: u64 = 4; // (size) -> user ptr | 0
pub const SYS_DEBUG: u64 = 5; // (ptr,len) -> write bytes to kernel serial log

pub const SYS_OPEN: u64 = 10; // (path_ptr,path_len,flags) -> fd | !0
pub const SYS_CLOSE: u64 = 11; // (fd)
pub const SYS_READ: u64 = 12; // (fd,buf,len) -> n | !0
pub const SYS_WRITE: u64 = 13; // (fd,buf,len) -> n | !0
pub const SYS_SEEK: u64 = 14; // (fd,offset,whence) -> pos | !0
pub const SYS_STAT: u64 = 15; // (path_ptr,len,&mut Stat) -> 0 | !0
pub const SYS_READDIR: u64 = 16; // (path_ptr,len,&mut DirEntry buf,max) -> n | !0
pub const SYS_MKDIR: u64 = 17; // (path_ptr,len)
pub const SYS_REMOVE: u64 = 18; // (path_ptr,len, is_dir)
pub const SYS_RENAME: u64 = 19; // (old_ptr,old_len,new_ptr,new_len)

pub const SYS_SHM_CREATE: u64 = 20; // (size) -> shm id | !0
pub const SYS_SHM_MAP: u64 = 21; // (id) -> ptr | 0
pub const SYS_SHM_DROP: u64 = 22; // (id)

pub const SYS_IPC_LISTEN: u64 = 30; // (name_ptr,len) -> port | !0
pub const SYS_IPC_CONNECT: u64 = 31; // (name_ptr,len) -> port | !0
pub const SYS_IPC_SEND: u64 = 32; // (port,buf,len)
pub const SYS_IPC_RECV: u64 = 33; // (port,buf,buflen,timeout_ms) -> n | 0 timeout | !0
pub const SYS_IPC_CLOSE: u64 = 34; // (port)
pub const SYS_IPC_OWNER: u64 = 35; // (port) -> owner pid | 0

pub const SYS_MEMINFO: u64 = 40; // (&mut MemInfo)
pub const SYS_TIME: u64 = 41; // (&mut DateTime)
pub const SYS_UPTIME_MS: u64 = 42; // -> ms
pub const SYS_PROCLIST: u64 = 43; // (&mut ProcInfo buf, max) -> n
pub const SYS_POWEROFF: u64 = 44;
pub const SYS_REBOOT: u64 = 45;
pub const SYS_FB_INFO: u64 = 46; // (&mut FbInfo) -> 0 | !0 (first claim wins)
pub const SYS_CHDIR: u64 = 47; // (path_ptr,len)
pub const SYS_GETCWD: u64 = 48; // (buf,len) -> n
pub const SYS_WAITPID: u64 = 49; // (pid,timeout_ms) -> exit_code | ERR
pub const SYS_KILL: u64 = 50; // (pid) -> 0 | ERR
pub const SYS_NET_PING: u64 = 51; // (ip u32 BE-packed, timeout_ms) -> rtt_ms | ERR
pub const SYS_NET_INFO: u64 = 52; // (&mut [u8;10] {mac[6],ip[4]}) -> 0 | ERR
pub const SYS_NET_DNS: u64 = 53; // (name_ptr,len, out [u8;4]) -> 0 | ERR (real UDP/53)
pub const SYS_NET_HTTP: u64 = 54; // (host_ptr,len, out, outlen) -> n | ERR (real TCP/80 GET /)
pub const SYS_NET_UDP_OPEN: u64 = 55; // (lport) -> 0 | ERR (bind local port)
pub const SYS_NET_UDP_SEND: u64 = 56; // (lport, dst_ip u32 BE-packed, dport, ptr, len) -> 0 | ERR
pub const SYS_NET_UDP_RECV: u64 = 57; // (lport, buf, cap, timeout_ms) -> n | ERR; buf=[srcip:4][sport:2][payload]
pub const SYS_NET_UDP_CLOSE: u64 = 58; // (lport) -> 0
pub const SYS_NET_DHCP: u64 = 59;      // () -> assigned ip (u32 BE-packed) | ERR
pub const SYS_NET_TCP_OPEN: u64 = 60;  // (lport, ip u32, rport) -> 0 | ERR (SYN handshake)
pub const SYS_NET_TCP_SEND: u64 = 61;  // (lport, ptr, len<=1400) -> 0 | ERR (retransmit till acked)
pub const SYS_NET_TCP_RECV: u64 = 62;  // (lport, buf, cap, timeout_ms) -> n | ERR
pub const SYS_NET_TCP_CLOSE: u64 = 63; // (lport) -> 0 (FIN + drop)
pub const SYS_CLIP_SET: u64 = 64;      // (ptr,len) -> 0 | ERR  (kernel clipboard)
pub const SYS_CLIP_GET: u64 = 65;      // (buf,cap) -> n | ERR
pub const SYS_NET_STAT: u64 = 66;      // (buf,cap) -> n | ERR  (socket table dump)
pub const SYS_DF: u64 = 67;            // (ptr to [u64;2]) -> 0 | ERR  {total_bytes, free_bytes}
pub const SYS_KLOG: u64 = 68;          // (buf,cap) -> n | ERR  kernel log ring tail
pub const SYS_ARP: u64 = 69;           // (buf,cap) -> n | ERR  ARP cache dump
pub const SYS_NET_TCP_LISTEN: u64 = 70;   // (lport) -> 0 | ERR  mark port listening
pub const SYS_NET_TCP_ACCEPT: u64 = 71;   // (lport, ptr to 8B out, timeout) -> cid | ERR
pub const SYS_NET_TCP_UNLISTEN: u64 = 72; // (lport) -> 0
pub const SYS_SHOT: u64 = 73;             // (path_ptr,path_len) -> 0 | ERR  fb -> PPM file
pub const SYS_RAND: u64 = 74;             // (buf,cap<=4096) -> n | ERR  hardware/seeded random bytes
pub const SYS_PCI_SCAN: u64 = 75;         // (&mut PciEnt buf, max) -> n | ERR
pub const SYS_BEEP: u64 = 76;             // (freq_hz, ms) -> 0  PC speaker via PIT ch2 + port 0x61

pub const SYS_GETPID: u64 = 77;           // () -> pid
pub const SYS_NICE: u64 = 78;             // (pid, nice) -> stored nice | -3
pub const SYS_PCAP: u64 = 79;             // (op, buf, cap) -> varies (see pcap.rs)
pub const SYS_STRACE: u64 = 80;           // (op,pid,buf,cap): 0 start 1 stop 2 drain
pub const SYS_KILL2: u64 = 81;            // (pid,sig): 9/15 kill, 19 STOP, 18 CONT -> 0 | ERR
pub const SYS_HOSTNAME_GET: u64 = 82;      // (buf,cap) -> n | ERR
pub const SYS_HOSTNAME_SET: u64 = 83;      // (ptr,len<=64) -> 0 | ERR
pub const SYS_ARP_DEL: u64 = 84;           // (ip as u32 BE) -> 1 deleted | 0 absent
pub const SYS_UTIME: u64 = 85;             // (path_ptr,len,secs) -> 0 | ERR  set file mtime
pub const SYS_SETATTR: u64 = 86;           // (path_ptr,len,attr) -> 0 | ERR  set FAT attr bits
pub const SYS_RTC_SET: u64 = 87;           // (unix_secs) -> 0            set wall clock (RTC + base)
pub const SYS_UMASK: u64 = 88;             // (mask|U64MAX=query) -> old   per-task file-create mask
pub const SYS_KLOG_CLEAR: u64 = 89;        // () -> 0                      clear the kernel log ring
pub const SYS_MKFIFO: u64 = 90;            // (path_ptr,len) -> 0 | ERR    create named pipe (mkfifo)
pub const SYS_READLINK: u64 = 91;          // (path_ptr,len,out,cap) -> len | ERR raw symlink target
pub const SYS_FLOCK: u64 = 92;             // (path_ptr,len,op) -> 0 | ERR  advisory file lock (LOCK_SH|EX|NB|UN)

// SYS_FLOCK op bits
pub const LOCK_SH: u64 = 1;
pub const LOCK_EX: u64 = 2;
pub const LOCK_NB: u64 = 4;
pub const LOCK_UN: u64 = 8;
pub const SYS_MUNMAP: u64 = 93;          // (addr,len) -> 0 | ERR   unmap tracked user mappings
pub const SYS_MPROTECT: u64 = 94;        // (addr,len,prot R|W|X=1|2|4) -> 0 | ERR
pub const SYS_CHRT: u64 = 95;            // (pid,class 0=other|1=rt) -> 0 | ERR  realtime class
pub const SYS_IPCS: u64 = 96;            // (buf,cap) -> n | ERR    shm registry dump
pub const SYS_PIPE: u64 = 97;            // () -> rfd | wfd<<32        anonymous pipe pair
pub const SYS_DUP2: u64 = 98;            // (oldfd,newfd) -> newfd | ERR  alias an fd
pub const SYS_POLL: u64 = 99;            // (fds,evs,nfds,timeout_ms) -> nready | ERR
pub const SYS_RUSAGE: u64 = 100;         // (pid,out{utime,stime,maxrss_kb}) -> 0 | ERR
pub const SYS_FSYNC: u64 = 101;          // (fd | u64::MAX=all) -> 0 | ERR   commit file/device
pub const SYS_INOTIFY_INIT: u64 = 102;   // () -> fd | ERR                 watch-instance fd
pub const SYS_INOTIFY_ADD: u64 = 103;    // (fd,path_ptr,len,mask) -> wd | ERR
pub const SYS_INOTIFY_RM: u64 = 104;     // (fd,wd) -> 0 | ERR
pub const SYS_TIMERFD: u64 = 105;        // () -> fd | ERR                 timer object fd
pub const SYS_TFD_SET: u64 = 106;        // (fd,init_ms,interval_ms) -> 0 | ERR
pub const SYS_EVENTFD: u64 = 107;        // (initval,flags) -> fd | ERR    event-counter fd
pub const SYS_EPOLL_CREATE: u64 = 108;   // () -> fd | ERR                 epoll interest-set fd
pub const SYS_EPOLL_CTL: u64 = 109;      // (epfd,op,fd,events) -> 0 | ERR add/del/mod an interest
pub const SYS_EPOLL_WAIT: u64 = 110;     // (epfd,out_ptr,max,timeout_ms) -> nready | ERR
pub const SYS_SOCKETPAIR: u64 = 111;     // () -> fdA | fdB<<32 | ERR
pub const SYS_PIDFD: u64 = 112;          // (pid) -> fd | ERR
pub const SYS_FCNTL: u64 = 113;          // (fd,cmd,arg) -> per-cmd | ERR
pub const F_DUPFD: u64 = 0;
pub const F_GETFL: u64 = 3;
pub const F_SETFL: u64 = 4;
pub const SYS_FSTAT: u64 = 114;          // (fd,&mut Stat) -> 0 | ERR
pub const SYS_FTRUNCATE: u64 = 115;      // (fd,len) -> 0 | ERR
pub const SYS_SENDFILE: u64 = 116;       // (out,in,off_ptr|0,count) -> n | ERR
pub const SYS_READV: u64 = 117;          // (fd,iov_ptr,iovcnt) -> n | ERR
pub const SYS_WRITEV: u64 = 118;         // (fd,iov_ptr,iovcnt) -> n | ERR
pub const SOCK_STREAM: u64 = 1;          // TCP socket
pub const SOCK_DGRAM: u64 = 2;           // UDP socket
pub const AF_UNIX: u64 = 1;              // unix-domain socket family
pub const AF_INET: u64 = 2;              // ipv4 socket family
pub const SYS_SOCKET: u64 = 119;         // (SOCK_*[, domain]) -> fd | ERR
pub const SYS_BIND: u64 = 120;           // (fd, lport|name_ptr, [len]) -> 0 | ERR
pub const SYS_CONNECT: u64 = 121;        // (fd, ip|name_ptr, port|len) -> 0 | ERR
pub const SYS_LISTEN: u64 = 122;         // (fd, backlog) -> 0 | ERR
pub const SYS_ACCEPT: u64 = 123;         // (fd, peer_out[8]|0) -> connfd | ERR
pub const SYS_SENDTO: u64 = 124;         // (fd, buf, len, ip u32 BE, port) -> n | ERR
pub const SYS_RECVFROM: u64 = 125;       // (fd, buf, cap, src_out[8]|0) -> n | ERR
pub const SYS_SHUTDOWN: u64 = 126;       // (fd, how 0=rd 1=wr 2=both) -> 0 | ERR
pub const SYS_GETSOCKNAME: u64 = 127;    // (fd, out, cap) -> n | ERR
pub const SYS_GETPEERNAME: u64 = 128;    // (fd, out, cap) -> n | ERR
pub const SYS_SENDMSG: u64 = 129;        // (fd, buf, len, passfd|usize::MAX) -> n | ERR
pub const SYS_RECVMSG: u64 = 130;        // (fd, buf, cap, fd_out|0) -> n | ERR
pub const SYS_SENDTO_PATH: u64 = 131;    // (fd, buf, len, name_ptr, name_len) -> n | ERR
pub const SYS_RECVFROM_PATH: u64 = 132;  // (fd, buf, cap, name_out|0, name_cap) -> n | ERR
pub const SYS_GETSOCKOPT: u64 = 133;     // (fd, level, opt, out, cap) -> n | ERR
pub const SYS_NET_TRACE: u64 = 134;      // (ip u32 BE, max_hops, out, cap) -> n | ERR
pub const SYS_SETSOCKOPT: u64 = 135;
pub const SYS_MMAP_FILE: u64 = 136;     // (fd, size, offset) -> user ptr | 0     // (fd, level, opt, val) -> 0 | errno
pub const SYS_CLONE: u64 = 137;        // (entry, arg) -> pid | !0  — thread in the caller's mm
pub const SYS_FUTEX: u64 = 138;        // (uaddr, op, val, timeout_ms) -> 0|n | -errno  — futex wait/wake
pub const SYS_FORK: u64 = 139;         // () -> pid | 0 (child) | !0  — eager copy-on-fork
pub const SYS_EXECVE: u64 = 140;       // (path_ptr,path_len,args_ptr,args_len) -> 0 | !0 — replaces the image
pub const SYS_SIGACTION: u64 = 141;    // (sig, handler) -> old handler | !0 — 0=DFL 1=IGN
pub const SYS_SIGRETURN: u64 = 142;    // () -> restores the pushed signal frame
pub const SYS_SIGPROCMASK: u64 = 143;    // (how 0=BLOCK 1=UNBLOCK 2=SETMASK, mask) -> old mask | !0
pub const SYS_SIGNALFD: u64 = 144;       // (mask) -> fd | !0 — reads pending sigs as 128B records
pub const SYS_ALARM: u64 = 145;          // (secs) -> prev remaining secs — SIGALRM one-shot
pub const SYS_SETSID: u64 = 146;         // () -> 0 | !0 — caller leads a new session+group
pub const SYS_SETPGID: u64 = 147;        // (pid, pgid; 0=self/same) -> 0 | !0
pub const SYS_GETPGID: u64 = 148;        // (pid; 0=self) -> pgid | !0
pub const SYS_GETSID: u64 = 149;         // (pid; 0=self) -> sid | !0
pub const SYS_PRCTL: u64 = 150;          // (op, arg) — op 1 = PR_SET_PDEATHSIG
pub const SYS_GETPPID: u64 = 151;        // () -> parent pid
pub const SYS_SIGPENDING: u64 = 152;     // () -> pending-signal bitmask
pub const SYS_SIGSUSPEND: u64 = 153;     // (mask) — sleep until deliverable
pub const SYS_ARCH_PRCTL: u64 = 154;     // (op, val) — 2=SET_FS, 3=GET_FS
pub const SYS_PRLIMIT: u64 = 155;
pub const SYS_SIGALTSTACK: u64 = 156;

// sigaction flags (a3)
pub const SA_RESTART: u8 = 1; // interrupted slow syscalls restart (no EINTR)
pub const SA_ONSTACK: u8 = 2; // run the handler on the sigaltstack stack
pub const SA_NODEFER: u8 = 4; // don't block this signal inside its own handler
// sigaltstack ss_flags
pub const SS_DISABLE: u64 = 2;

pub const SYS_PTRACE: u64 = 157;
pub const SYS_WAITID: u64 = 158; // (idtype, id, flags) -> (pid<<32)|(kind<<24)|status
pub const SYS_EXIT_GROUP: u64 = 159;   // (code) -> !  kill every thread of the mm
pub const SYS_GETTID: u64 = 160;       // () -> tid (task id of this thread)
pub const SYS_TGKILL: u64 = 161;       // (tgid, tid, sig) -> 0 | err
pub const SYS_SETITIMER: u64 = 162;    // (which, init_ms, interval_ms) -> 0
pub const SYS_GETITIMER: u64 = 163;    // (which) -> (cur_ms<<32)|int_ms
pub const SYS_MQ_OPEN: u64 = 164;      // (name_ptr,len,maxmsg,msgsize) -> fd|err
pub const SYS_MQ_SEND: u64 = 165;      // (fd,buf,len,prio) -> 0|err
pub const SYS_MQ_RECV: u64 = 166;      // (fd,buf,len) -> n | prio<<32 | err
pub const SYS_MQ_UNLINK: u64 = 167;    // (name_ptr,len) -> 0|err
pub const SYS_MEMFD_CREATE: u64 = 168; // (name_ptr,len) -> fd|err
pub const SYS_TIMER_CREATE: u64 = 169; // (sig) -> timer id|err
pub const SYS_TIMER_SETTIME: u64 = 170;// (id, init_ms, int_ms) -> 0|err
pub const SYS_TIMER_DELETE: u64 = 171; // (id) -> 0|err
pub const SYS_CLOCK_GETTIME: u64 = 172;// (clkid, out_ptr) -> 0|err
                                     // clkid 0=REALTIME(rtc) 1=MONOTONIC
pub const SYS_SPLICE: u64 = 173;       // (in_fd, out_fd, len) -> moved|err
pub const SYS_PROCESS_VM: u64 = 174;   // (pid, addr, buf, len, wr) -> n|err
pub const SYS_PPOLL: u64 = 175;        // (fds,evs,nfds,timeout,mask) -> n|err
pub const SYS_SYSINFO: u64 = 176;      // (out_ptr) -> 0|err
pub const SYS_CLOSE_RANGE: u64 = 177;  // (first,last) -> 0|err
pub const SYS_PIDFD_SIGNAL: u64 = 178; // (pidfd, sig) -> 0|err
pub const SYS_OPENPT: u64 = 179;        // () -> master fd (/ptym/{id})
pub const SYS_TCSETS: u64 = 180;        // (pty_fd, flags) -> 0|err
pub const SYS_TCGETS: u64 = 181;        // (pty_fd) -> flags|err
pub const SYS_PTSNAME: u64 = 182;       // (master_fd, out, len) -> 0|err
pub const SYS_OPENAT: u64 = 183;        // (dirfd, path,len, flags) -> fd|err  AT_FDCWD
pub const SYS_FSTATAT: u64 = 184;       // (dirfd, path,len, flags, &mut Stat) -> 0|err
pub const SYS_FACCESSAT: u64 = 185;     // (dirfd, path,len, mode) -> 0|err
pub const SYS_UNLINKAT: u64 = 186;      // (dirfd, path,len, flags) -> 0|err  AT_REMOVEDIR
pub const SYS_RENAMEAT: u64 = 187;      // (odfd,opath,olen, ndfd,npath,nlen) -> 0|err
pub const SYS_MKDIRAT: u64 = 188;       // (dirfd, path,len) -> 0|err
pub const SYS_LINKAT: u64 = 189;        // (odfd,opath,olen, ndfd,npath,nlen) -> -38 (FAT: no hard links)
pub const SYS_SYMLINKAT: u64 = 190;     // (target_ptr,tlen, ndfd,npath,nlen) -> 0|err
pub const SYS_READLINKAT: u64 = 191;    // (dirfd, path,len, out,cap) -> n|err
pub const SYS_FCHDIR: u64 = 193;        // (fd) -> 0|err   chdir to a dir fd's path
pub const SYS_FCHMOD: u64 = 194;        // (fd, mode) -> 0|err  FAT: bit0 -> ro attr
pub const SYS_GETDENTS: u64 = 195;      // (fd, &mut DirEntry, max) -> n|err
pub const SYS_ACCESS: u64 = 196;        // (path,len, mode) -> 0|err
pub const SYS_WAIT4: u64 = 197;         // (pid, opts, timeout, rusage_ptr) -> status|err
pub const AT_FDCWD: i64 = -100;
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
pub const AT_REMOVEDIR: u64 = 0x200;
pub const AT_EMPTY_PATH: u64 = 0x1000;
pub const O_EXCL: u64 = 128;
pub const O_PATH: u64 = 256;
pub const O_NOCTTY: u64 = 512; // don't acquire the tty as controlling
pub const SYS_SECCOMP: u64 = 198;       // (mode, allow_ptr, len32B) -> 0|err  1=strict 2=bitmap
pub const SYS_SET_ROBUST_LIST: u64 = 199;// (head_va) -> 0  node={next, futex_va}
pub const SYS_STATFS: u64 = 200;        // (path,len,&mut Statfs{type,bsize,blocks,bfree}) -> 0|err
pub const SYS_FSTATFS: u64 = 201;       // (fd,&mut Statfs) -> 0|err
pub const SYS_SYNCFS: u64 = 202;        // (fd) -> 0|err   flush the fd's volume
pub const SYS_FALLOCATE: u64 = 203;     // (fd,off,len) -> 0|err  zero-extend file
pub const SYS_COPY_FILE_RANGE: u64 = 204;// (in_fd,out_fd,off_packed?) len via a4 -> n|err
pub const SYS_TEE: u64 = 205;           // (in_pipe_fd,out_pipe_fd,len) -> n|err (dup, no consume)
pub const SYS_PSELECT: u64 = 206;       // (nfds,rmask_ptr,wmask_ptr,timeout_ms,mask) -> n|err
pub const SYS_DUP3: u64 = 207;          // (oldfd,newfd,flags) -> newfd|err
pub const SYS_SCHED_YIELD: u64 = 208;   // () -> 0
pub const SYS_CLOCK_NANOSLEEP: u64 = 209;// (clock_id, abs_ms) -> 0|err (TIMER_ABSTIME)
pub const SYS_GETTIMEOFDAY: u64 = 210;  // (&mut {sec,usec}) -> 0|err
pub const SYS_SET_TID_ADDRESS: u64 = 211; // (tidptr) -> tid — child sets its own ctid addr
pub const SYS_RENAMEAT2: u64 = 212;       // (&[u64;7]{odfd,optr,olen,ndfd,nptr,nlen,flags})
pub const SYS_UTIMENSAT: u64 = 213;       // (dirfd,path,plen,times_ptr[4u64]|0,flags)
pub const SYS_PIPE2: u64 = 214;           // (flags: O_NONBLOCK|O_CLOEXEC) -> rfd|wfd<<32
pub const SYS_EVENTFD2: u64 = 215;        // (initval, flags: SEM|NONBLOCK|CLOEXEC) -> fd
pub const SYS_MOUNT: u64 = 216;           // (&[u64;6]{sptr,slen,tptr,tlen,fptr,flen})
pub const SYS_UMOUNT: u64 = 217;
/// chroot(dir): jail the task's path resolution under `dir` (root field).
pub const SYS_CHROOT: u64 = 218;
/// statx(&[u64;6]{dirfd,path,len,flags,mask,&mut Statx}) -> 0|err
pub const SYS_STATX: u64 = 219;
/// mount() flags
pub const MS_RDONLY: u64 = 1;
pub const MS_REMOUNT: u64 = 32;
/// MS_BIND: source is an existing path aliased onto target.
pub const MS_BIND: u64 = 0x1000;
/// umount flags
pub const MNT_FORCE: u64 = 1;
pub const MNT_DETACH: u64 = 2;
/// statx flags (reuse AT_* where identical)
pub const AT_STATX_SYMLINK_NOFOLLOW: u64 = 0x100;
pub const STATX_ALL: u64 = 0xfff;
/// pivot_root(&[u64;4]{new_ptr,new_len,old_ptr,old_len})
pub const SYS_PIVOT_ROOT: u64 = 220;
/// openat2(&[u64;6]{dirfd,path,len,flags,mode,resolve})
pub const SYS_OPENAT2: u64 = 221;
/// getrandom(buf, len, flags)
pub const SYS_GETRANDOM: u64 = 222;
/// mincore(addr, len, vec_out) — per-page residency bits
pub const SYS_MINCORE: u64 = 223;
/// madvise(addr, len, advice)
pub const SYS_MADVISE: u64 = 224;
/// unshare(flags) — CLONE_NEWNS deep-copies the mount namespace
pub const SYS_UNSHARE: u64 = 225;
/// setns(fd) — adopt the namespace behind /proc/<pid>/ns/mntns
pub const SYS_SETNS: u64 = 226;
/// pidfd_getfd(pidfd, fd, flags) — duplicate a descriptor out of another task
pub const SYS_PIDFD_GETFD: u64 = 229;
/// syslog(action, buf, len) — kernel log ring access
pub const SYS_SYSLOG: u64 = 230;
/// timerfd_gettime(fd, &mut [u64;2]{init_ms,interval_ms})
pub const SYS_TFD_GET: u64 = 231;
/// getuid/geteuid/getgid/getegid() -> u32 id
pub const SYS_GETUID: u64 = 233;
pub const SYS_GETEUID: u64 = 234;
pub const SYS_GETGID: u64 = 235;
pub const SYS_GETEGID: u64 = 236;
/// setuid(uid) / setgid(gid): root sets real+eff; non-root may only
/// switch euid back to its real id (EPERM otherwise)
pub const SYS_SETUID: u64 = 237;
pub const SYS_SETGID: u64 = 238;
/// chown(path_ptr,len,uid,gid; u64::MAX=unchanged) — EPERM on FAT
/// (vfat has no owners) and for non-root
pub const SYS_CHOWN: u64 = 239;
/// fchown(fd,uid,gid)
pub const SYS_FCHOWN: u64 = 240;
/// chmod(path_ptr,len,mode): tmpfs stores real mode bits; FAT maps
/// owner-w onto the readonly attr (vfat-style), root only
pub const SYS_CHMOD: u64 = 241;
pub const SYS_TCGETPGRP: u64 = 242;      // (pty_fd) -> fg pgid | err
pub const SYS_TCSETPGRP: u64 = 243;      // (pty_fd, pgid) -> 0 | err
pub const SYS_TIOCSTI: u64 = 244;        // (pty_fd, byte) -> 0 | err (root only)
pub const SYS_GETGROUPS: u64 = 245;      // (out u32[], cap) -> count | err
pub const SYS_SETGROUPS: u64 = 246;      // (u32[], count) -> 0 | err (root only)
pub const SYS_SETRESUID: u64 = 247;      // (ruid,euid,suid u32::MAX=keep) -> 0|EPERM
pub const SYS_SETRESGID: u64 = 248;      // same shape for gids
pub const SYS_GETRESUID: u64 = 249;      // (out u32[3]) -> 0 | err
pub const SYS_GETRESGID: u64 = 250;
/// (pid, out u64[3]{eff,prm,bnd}) — pid 0 = caller.
pub const SYS_CAPGET: u64 = 251;
/// (pid, in u64[2]{eff,prm}) — self only; prm ⊆ bnd, eff ⊆ prm.
pub const SYS_CAPSET: u64 = 252;      // (out u32[3]) -> 0 | err
pub const SYS_RDMSR: u64 = 253;        // (msr u64) -> u64 | err -38 (whitelisted regs)
/// MS_MOVE: move a mount point instead of creating one
pub const MS_MOVE: u64 = 0x2000;
/// CLONE_NEWUTS: unshare the UTS namespace (hostname)
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
/// CLONE_NEWIPC: unshare a fresh IPC namespace (moves the caller).
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
/// CLONE_NEWTIME: stage a fresh time namespace for future children.
pub const CLONE_NEWTIME: u64 = 0x80;
/// CLONE_NEWUSER: unshare a fresh user namespace (moves the caller).
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
/// CLONE_NEWPID: unshare/setns a PID namespace — children land inside
/// (pidns_for_children semantics), the caller never moves.
pub const CLONE_NEWPID: u64 = 0x2000_0000;
/// LINUX_REBOOT_CMD values for SYS_REBOOT
pub const RB_RESTART: u64 = 0x0123_4567;
pub const RB_HALT: u64 = 0xcdef_0123;
pub const RB_POWER_OFF: u64 = 0x4321_fedc;
pub const RB_MAGIC1: u64 = 0xfee1_dead;
pub const RB_MAGIC2: u64 = 0x2812_1969;
/// MS_NOSUID: ignore setuid bits under the mount
pub const MS_NOSUID: u64 = 2;
/// MS_NODEV: do not interpret device files under the mount
pub const MS_NODEV: u64 = 4;
/// MS_NOEXEC: disallow program execution from the mount
pub const MS_NOEXEC: u64 = 8;
pub const CLONE_NEWNS: u64 = 0x0002_0000;
/// openat2 resolve flags
pub const RESOLVE_NO_XDEV: u64 = 1;
pub const RESOLVE_NO_SYMLINKS: u64 = 2;
pub const RESOLVE_BENEATH: u64 = 4;
pub const RESOLVE_IN_ROOT: u64 = 8;
/// madvise advice values (subset)
pub const MADV_DONTNEED: u64 = 4;
pub const MADV_WILLNEED: u64 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Statx {
    pub mask: u32,
    pub blksize: u32,
    pub attr: u64,   // FAT attribute byte
    pub nlink: u64,
    pub mode: u32,   // unix-style type+perm bits
    pub _pad: u32,
    pub ino: u64,    // stable FNV-1a of the canonical path
    pub size: u64,
    pub blocks: u64, // 512B units
    pub mtime: u64,
    pub ctime: u64,
    pub btime: u64,
    pub uid: u32,
    pub gid: u32,
}          // (target_ptr, len) -> 0|err
pub const O_CLOEXEC: u64 = 0x10000;       // per-desc flag: close on successful exec
pub const F_GETFD: u64 = 1;               // fcntl: get descriptor flags
pub const F_SETFD: u64 = 2;               // fcntl: set descriptor flags (FD_CLOEXEC)
pub const RENAME_NOREPLACE: u64 = 1;      // renameat2: fail if target exists
pub const RENAME_EXCHANGE: u64 = 2;       // renameat2: swap the two names
pub const EFD_NONBLOCK: u64 = 0x40;       // eventfd2 flag = O_NONBLOCK
pub const EFD_CLOEXEC: u64 = O_CLOEXEC;   // eventfd2 flag
pub const SECCOMP_MODE_STRICT: u64 = 1;
pub const SECCOMP_MODE_FILTER: u64 = 2;

// ptrace request ops
pub const PT_TRACEME: u64 = 0;
pub const PT_PEEK: u64 = 1;
pub const PT_POKE: u64 = 4;
pub const PT_CONT: u64 = 7;
pub const PT_KILL: u64 = 8;
pub const PT_STEP: u64 = 9;
pub const PT_GETREGS: u64 = 12;
pub const PT_SETREGS: u64 = 13;
pub const PT_ATTACH: u64 = 16;
pub const PT_DETACH: u64 = 17;
pub const PT_PEEKUSER: u64 = 3;
pub const PT_POKEUSER: u64 = 6;
pub const PT_SYSCALL: u64 = 24;
pub const PT_GETSIGINFO: u64 = 0x4202; // (pid, 0, out) -> writes si_signo/errno/code

/// Register file layout == the kernel's saved CpuContext (PTRACE_GETREGS).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PtRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}        // (pid, res, new_or_MAX, old_ptr)
pub const SOL_SOCKET: u64 = 1;
pub const SO_REUSEADDR: u64 = 2;
pub const SO_TYPE: u64 = 3;
pub const SO_ERROR: u64 = 4;
pub const SO_SNDBUF: u64 = 7;
pub const SO_RCVBUF: u64 = 8;
pub const SO_BROADCAST: u64 = 6;
pub const SO_KEEPALIVE: u64 = 9;
pub const SO_RCVTIMEO: u64 = 20;
pub const SO_SNDTIMEO: u64 = 21;
pub const SO_ACCEPTCONN: u64 = 30;
pub const SO_PROTOCOL: u64 = 38;
pub const SO_DOMAIN: u64 = 39;
pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;
pub const PROT_EXEC: u64 = 4;
pub const SCHED_OTHER: u64 = 0;
pub const SCHED_RT: u64 = 1;
pub const SYS_ERR: u64 = u64::MAX;

// open flags
pub const O_RDONLY: u64 = 0;
pub const O_WRONLY: u64 = 1;
pub const O_RDWR: u64 = 2;
pub const O_CREATE: u64 = 4;
pub const O_TRUNC: u64 = 8;
pub const O_APPEND: u64 = 16;
pub const O_NONBLOCK: u64 = 64;

// seek whence
pub const SEEK_SET: u64 = 0;
pub const SEEK_CUR: u64 = 1;
pub const SEEK_END: u64 = 2;

// ---------------------------------------------------------------------------
// Kernel-provided structs
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MemInfo {
    pub total_kb: u64,
    pub used_kb: u64,
    pub kernel_heap_kb: u64,
    pub tasks: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcInfo {
    pub pid: u32,
    pub is_user: u32,
    pub mem_kb: u64,
    pub cpu_ticks: u64, // 10ms PIT ticks this task has run
    pub name: [u8; 32],
}
impl Default for ProcInfo {
    fn default() -> Self {
        Self { pid: 0, is_user: 0, mem_kb: 0, cpu_ticks: 0, name: [0; 32] }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Stat {
    pub size: u64,
    pub is_dir: u32,
    pub mtime: u64, // seconds since unix epoch (0 if unknown)
    pub attr: u32,  // FAT attribute byte (0 on pseudo-fs)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DirEntry {
    pub name: [u8; 96],
    pub name_len: u8,
    pub is_dir: u8,
    pub size: u64,
    pub mtime: u64,
    pub attr: u8,   // FAT attribute byte (0 on pseudo-fs)
}
impl Default for DirEntry {
    fn default() -> Self {
        Self { name: [0; 96], name_len: 0, is_dir: 0, size: 0, mtime: 0, attr: 0 }
    }
}
pub const DIR_ENTRY_MAX: usize = 64;

/// One PCI function, filled by SYS_PCI_SCAN.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PciEnt {
    pub bus: u8,
    pub dev: u8,
    pub fun: u8,
    pub class: u8,    // base class code (cfg 0x0B)
    pub subclass: u8, // cfg 0x0A
    pub _pad: u8,
    pub vendor: u16,
    pub device: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FbInfo {
    pub addr: u64, // user-space virtual address of mapped framebuffer
    pub width: u32,
    pub height: u32,
    pub stride: u32, // pixels per row
    pub bpp: u16,    // bits per pixel (32 = BGRX/XRGB)
    pub format: u8,  // 0 = BGR, 1 = RGB
}

// ---------------------------------------------------------------------------
// Input events: kernel -> winserver ("cosmos:input" port)
// ---------------------------------------------------------------------------
pub const INPUT_PORT: &str = "cosmos:input";
pub const WS_PORT: &str = "cosmos:win";

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Key = 1,
    Mouse = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InputKey {
    pub kind: u8, // InputKind::Key
    pub down: u8,
    pub chr: u8, // ASCII char if printable (0 otherwise)
    pub mods: u8, // bit0 ctrl, bit1 shift, bit2 alt, bit3 super
    pub key: u32, // KeyCode
    pub scancode: u32, // raw set-1 scancode (with E0 bit 8 set for extended)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InputMouse {
    pub kind: u8, // InputKind::Mouse
    pub buttons: u8, // bit0 left, bit1 right, bit2 middle
    pub dx: i16,
    pub dy: i16,
    pub wheel: i8,
    pub _pad: u8,
}

// ---------------------------------------------------------------------------
// Window server protocol (over "cosmos:win" ipc port)
// Message = WsHeader { kind, len } followed by payload bytes.
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WsHeader {
    pub kind: u16,
    pub len: u16,   // payload bytes following the header
    pub reply: u32, // sender's reply/event port (client -> server requests)
}

// request kinds (app -> winserver)
pub const REQ_CREATE_WIN: u16 = 1;
pub const REQ_PRESENT: u16 = 2;
pub const REQ_SET_TITLE: u16 = 3;
pub const REQ_CLOSE_WIN: u16 = 4;
pub const REQ_PING: u16 = 5;
pub const REQ_LIST_WINS: u16 = 7;  // () -> RSP_WIN_LIST (WinInfo[])
pub const REQ_FOCUS_WIN: u16 = 8;  // (window_id u32) raise + focus + unmin
pub const REQ_MOVE_WIN: u16 = 9;   // (ReqMoveWin) reposition top-left
pub const REQ_SWITCH_WS: u16 = 10; // (u32) switch active workspace
// response kinds (winserver -> app)
pub const RSP_WIN_CREATED: u16 = 100;
pub const RSP_ERROR: u16 = 101;
pub const RSP_WIN_LIST: u16 = 110;
// event kinds (winserver -> app)
pub const EV_KEY: u16 = 200;
pub const EV_POINTER: u16 = 201;
pub const EV_FOCUS: u16 = 202;
pub const EV_CLOSE: u16 = 203;
pub const EV_RESIZE_REQ: u16 = 204;
// resize ack (app -> winserver)
pub const REQ_RESIZE_ACK: u16 = 6;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReqCreateWin {
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
    pub flags: u32, // bit0: decorate, bit1: resizable
    pub title: [u8; 48],
}
pub const WIN_DECORATE: u32 = 1;
pub const WIN_RESIZABLE: u32 = 2;

/// Window decoration metrics used by the compositor (shared with apps so
/// they can lay out their client area consistently).
pub const TITLE_H: u32 = 26;
pub const BORDER_W: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RspWinCreated {
    pub window_id: u32,
    pub shm_id: u32,
    pub w: u32,
    pub h: u32,
    pub stride: u32, // pixels per row in the shm surface
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReqPresent {
    pub window_id: u32,
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32, // dirty rect in window coords; w=0 => whole window
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReqSetTitle {
    pub window_id: u32,
    pub title: [u8; 48],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReqMoveWin {
    pub window_id: u32,
    pub x: i32,
    pub y: i32,
}

/// One row of the REQ_LIST_WINS reply (payload = WinInfo[] of all windows,
/// focused workspace first is NOT implied -- order is z-order).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WinInfo {
    pub id: u32,
    pub pid: u32,
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
    pub ws: u32,
    pub state: u8, // bit0 minimized, bit1 focused, bit2 maximized
    pub _pad: [u8; 3],
    pub title: [u8; 48],
}
pub const WIN_ST_MIN: u8 = 1;
pub const WIN_ST_FOCUS: u8 = 2;
pub const WIN_ST_MAX: u8 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EvKey {
    pub window_id: u32,
    pub key: u32, // KeyCode
    pub chr: u8,  // ASCII char if printable
    pub down: u8,
    pub mods: u8, // bit0 ctrl, bit1 shift, bit2 alt, bit3 super
    pub _pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EvPointer {
    pub window_id: u32,
    pub x: i32,
    pub y: i32,     // window-relative
    pub buttons: u8, // current button state
    pub wheel: i8,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EvFocus {
    pub window_id: u32,
    pub focused: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EvResizeReq {
    pub window_id: u32,
    pub w: u32,
    pub h: u32,
    pub shm_id: u32, // new backing surface created by the server
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReqResizeAck {
    pub window_id: u32,
    pub shm_id: u32,
    pub w: u32,
    pub h: u32,
}

/// Keyboard key codes delivered to apps (abstracted from scancodes).
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyCode {
    None = 0,
    Char = 1, // printable char; see `chr` field
    Enter = 2,
    Backspace = 3,
    Tab = 4,
    Escape = 5,
    Left = 6,
    Right = 7,
    Up = 8,
    Down = 9,
    Home = 10,
    End = 11,
    PageUp = 12,
    PageDown = 13,
    Delete = 14,
    F1 = 15,
    F2 = 16,
    F3 = 17,
    F4 = 18,
    F5 = 19,
    F6 = 20,
    F7 = 21,
    F8 = 22,
    F9 = 23,
    F10 = 24,
    F11 = 25,
    F12 = 26,
    Super = 27,
    Ctrl = 28,
    Alt = 29,
    Shift = 30,
}

/// IPC payload ceiling for window protocol messages.
pub const WS_MSG_MAX: usize = 256;
