#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 64 

static __always_inline int is_malicious_path(const char *path) {
    if (path[0] == '/' && path[1] == 'b' && path[2] == 'i' && path[3] == 'n' && path[4] == '/') {
        if (path[5] == 'b' && path[6] == 'a' && path[7] == 's' && path[8] == 'h') return 1;
        if (path[5] == 's' && path[6] == 'h' && path[7] == '\0') return 1;
        if (path[5] == 'n' && path[6] == 'c' && path[7] == '\0') return 1;
        if (path[5] == 'w' && path[6] == 'g' && path[7] == 'e' && path[8] == 't') return 1;
        if (path[5] == 'c' && path[6] == 'u' && path[7] == 'r' && path[8] == 'l') return 1;
    }
    if (path[0] == '/' && path[1] == 'u' && path[2] == 's' && path[3] == 'r' && path[4] == '/' &&
        path[5] == 'b' && path[6] == 'i' && path[7] == 'n' && path[8] == '/') {
        if (path[9] == 'p' && path[10] == 'y' && path[11] == 't') return 1;
        if (path[9] == 'p' && path[10] == 'e' && path[11] == 'r' && path[12] == 'l') return 1;
    }
    return 0;
}

static __always_inline int is_web_server(const char *comm) {
    if (comm[0] == 'p' && comm[1] == 'h' && comm[2] == 'p') return 1;
    if (comm[0] == 'a' && comm[1] == 'p' && comm[2] == 'a') return 1;
    if (comm[0] == 'n' && comm[1] == 'g' && comm[2] == 'i') return 1;
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(block_web_rce, struct linux_binprm *bprm, int ret) {
    if (ret != 0) return ret; 

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    char current_comm[TASK_COMM_LEN];
    bpf_get_current_comm(&current_comm, sizeof(current_comm));

    if (current_comm[0] == 'c' && current_comm[1] == 'r' && current_comm[2] == 'o') return 0;
    if (current_comm[0] == 's' && current_comm[1] == 'y' && current_comm[2] == 's') return 0;
    if (current_comm[0] == 's' && current_comm[1] == 's' && current_comm[2] == 'h') return 0;

    if (is_web_server(current_comm)) {
        const char *filename = BPF_CORE_READ(bprm, filename);
        char path_buf[MAX_PATH_LEN];
        if (bpf_probe_read_kernel_str(path_buf, MAX_PATH_LEN, filename) > 0) {
            if (is_malicious_path(path_buf)) return -1; 
        }

        const char *interp = BPF_CORE_READ(bprm, interp);
        if (interp) {
            char interp_buf[MAX_PATH_LEN];
            if (bpf_probe_read_kernel_str(interp_buf, MAX_PATH_LEN, interp) > 0) {
                if (is_malicious_path(interp_buf)) return -1; 
            }
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
