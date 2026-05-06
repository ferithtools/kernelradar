#pragma once
/* Types come from vmlinux.h — do NOT include <linux/types.h> here */

/* ── Event identifiers ───────────────────────────────────────────────── */

#define KR_DETECTOR_PRIVESC     1
#define KR_DETECTOR_BPF_LOADER  2
#define KR_DETECTOR_CONTAINER   3
#define KR_DETECTOR_KMOD        4
#define KR_DETECTOR_FIM         5

#define KR_SEV_INFO     0
#define KR_SEV_WARNING  1
#define KR_SEV_ALERT    2
#define KR_SEV_CRITICAL 3

/* ── PrivEsc event types ─────────────────────────────────────────────── */

#define KR_PRIVESC_SETUID       1   /* setuid() call */
#define KR_PRIVESC_SETGID       2   /* setgid() call */
#define KR_PRIVESC_SETRESUID    3   /* setresuid() call */
#define KR_PRIVESC_SETRESGID    4   /* setresgid() call */
#define KR_PRIVESC_EXEC_SUID    5   /* exec of setuid binary */

/* ── BPF loader event types ─────────────────────────────────────────── */

#define KR_BPF_PROG_LOAD        1   /* BPF_PROG_LOAD from unknown process */

/* ── FIM event types ────────────────────────────────────────────────── */

#define KR_FIM_OPEN_WRITE       1   /* openat() with write/append/create */

/* ── Common event struct (must match Rust KrEvent) ───────────────────── */

struct kr_event {
    __u64  timestamp_ns;
    __u32  pid;
    __u32  tid;
    __u32  uid;
    __u32  gid;
    __u8   comm[16];
    __u8   detector_id;
    __u8   severity;
    __u16  event_type;
    __u64  data[4];          /* 32 bytes detector-specific payload */
};
