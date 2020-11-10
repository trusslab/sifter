#include <linux/seccomp.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include <bpf_helpers.h>
#include <linux/errno.h>
#include <sys/types.h>
#include <linux/android/binder.h>

#define bpf_printk(fmt, ...)                                    \
({                                                              \
    char ____fmt[] = fmt;                                       \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);  \
})

struct pt_regs {
    union {
        struct user_pt_regs user_regs;
        struct {
            uint64_t regs[31];
            uint64_t sp;
            uint64_t pc;
            uint64_t pstate;
        };
    };
    uint64_t orig_x0;
    uint64_t syscallno;
    uint64_t orig_addr_limit;
    uint64_t unused; // maintain 16 byte alignment
};

#define PID_MAX 32768

typedef struct {
    struct bpf_spin_lock lock;
    uint8_t next;
    uint16_t id0[128];
    uint16_t id1[128];
} seq_rb_elem;

// syscall sequence ringbuffer
DEFINE_BPF_MAP_F(syscall_seq_rb, ARRAY, int, seq_rb_elem, PID_MAX, BPF_F_LOCK);
DEFINE_BPF_MAP(syscall_seq_rb_ctr, ARRAY, int, uint8_t, PID_MAX);

void __always_inline update_syscall_seq(int pid, uint16_t id) {
    seq_rb_elem *rb = bpf_syscall_seq_rb_lookup_elem(&pid);
    if (rb) {
        uint8_t next;
        bpf_spin_lock(&rb->lock);
        next = rb->next;
        next += 1;
        rb->next = next;
        bpf_spin_unlock(&rb->lock);

        if (next-1 < 128)
            rb->id0[next-1] = id;
        else
            rb->id1[next-129] = id;

        uint8_t *ctr = bpf_syscall_seq_rb_ctr_lookup_elem(&pid);
        if (ctr && (next == 0 || next == 128)) {
            *ctr += 1;
        }
    }
}

int __always_inline get_current_pid() {
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    int pid = current_pid_tgid >> 32;
    return pid;
}

struct sys_enter_args {
    uint64_t ignore;
    int64_t id;
    uint64_t regs[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter_prog(struct sys_enter_args *arg) {
    uint16_t id = arg->id;
    uint32_t pid = get_current_pid();
    update_syscall_seq(pid, id);
    return 0;
}

char _license[] SEC("license") = "GPL";
