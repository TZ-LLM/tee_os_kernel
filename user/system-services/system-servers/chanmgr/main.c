/*
 * Copyright (c) 2023 Institute of Parallel And Distributed Systems (IPADS), Shanghai Jiao Tong University (SJTU)
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include <chcore/ipc.h>
#include <chcore/syscall.h>
#include <chcore-internal/chanmgr_defs.h>
#include <errno.h>
#include <chanmgr.h>
#include <pthread.h>
#include <chcore/memory.h>
#include <string.h>
#include <chcore/launcher.h>
#include <chcore/proc.h>
#include <chcore/defs.h>
#include <chcore/llm.h>

void chanmgr_dispatch(ipc_msg_t *ipc_msg, badge_t client_badge, int pid,
                      int tid)
{
    struct chan_request *req;

    req = (struct chan_request *)ipc_get_msg_data(ipc_msg);

    switch (req->req) {
    case CHAN_REQ_CREATE_CHANNEL:
        chanmgr_handle_create_channel(ipc_msg, client_badge, pid, tid);
        break;
    case CHAN_REQ_REMOVE_CHANNEL:
        chanmgr_handle_remove_channel(ipc_msg, client_badge, pid, tid);
        break;
    case CHAN_REQ_HUNT_BY_NAME:
        chanmgr_handle_hunt_by_name(ipc_msg, pid, tid);
        break;
    case CHAN_REQ_GET_CH_FROM_PATH:
        chanmgr_handle_get_ch_from_path(ipc_msg, pid, tid);
        break;
    case CHAN_REQ_GET_CH_FROM_TASKID:
        chanmgr_handle_get_ch_from_taskid(ipc_msg, pid, tid);
        break;
    default:
        ipc_return(ipc_msg, -EBADRQC);
        break;
    }
}

#define NUM_THREADS 10

pthread_mutex_t mutex;
pthread_cond_t cond_var;

void* worker(void* arg) {
    int thread_id = *(int*)arg;
    free(arg);

    int cnt = 0;
    while (true) {
        pthread_mutex_lock(&mutex);
        printf("Thread %d is waiting.\n", thread_id);
        pthread_cond_wait(&cond_var, &mutex);
        printf("Thread %d is awakened counter %d.\n", thread_id, cnt);
        pthread_mutex_unlock(&mutex);

        while (true) {
            int sum = 0;
            for (int i = 0; i < 1000000000; i++) {
                sum += (i ^ 123154231);
            }
            printf("sum %d\n", sum);
        }
    }

    return NULL;
}

void *idle(void *arg) {
    usys_disable_local_irq();
    usys_set_prio(0, 1);
    usys_yield();
    while (1) {
        struct smc_registers regs = {0};
        usys_tee_switch_req(&regs);
    }
}

void *loop(void *) {
    while (1);
}

int master() {
    pthread_t threads[NUM_THREADS];
    struct smc_registers req = {0};

    pthread_t loop_thread;

    printf("SHM INIT: Main thread is waiting for smc\n");
    unsigned long paddr = usys_tee_wait_switch_req(&req);
    printf("SHM INIT: Main thread is awaken from smc\n");
    unsigned long size = CMD_QUEUE_SHM_SIZE;
    printf("received shm addr %p size %lx\n", (void *)paddr, size);
    cap_t pmo = usys_tee_create_ns_pmo(paddr, size);
    void *vaddr = chcore_auto_map_pmo(pmo, size, VMR_READ | VMR_WRITE);

    sprintf((char *)vaddr, "msg from tee\n");

    if (0) {
        printf("Main thread is waiting for smc\n");
        usys_tee_wait_switch_req(&req);
        printf("Main thread is awaken from smc\n");

    #define LLM_MODEL_SIZE (4ul * 1024 * 1024 * 1024)
        printf("%s %d\n", __func__, __LINE__);
        cap_t pmo = usys_create_s2_pmo(0, LLM_MODEL_SIZE / PAGE_SIZE);
        printf("%s %d\n", __func__, __LINE__);
        void *buf = chcore_auto_map_pmo(pmo, LLM_MODEL_SIZE, VMR_READ | VMR_WRITE);
        printf("%s %d\n", __func__, __LINE__);
        memset(buf, 0, LLM_MODEL_SIZE);
        printf("%s %d\n", __func__, __LINE__);
        chcore_auto_unmap_pmo(pmo, (unsigned long)buf, LLM_MODEL_SIZE);
        printf("%s %d\n", __func__, __LINE__);

        printf("Main thread is waiting for smc\n");
        usys_tee_wait_switch_req(&req);
        printf("Main thread is awaken from smc\n");
    }

    // Initialize mutex and condition variable
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&cond_var, NULL);

    // Create worker threads
    for (int i = 0; i < NUM_THREADS; i++) {
        int* thread_id = malloc(sizeof(int));
        *thread_id = i;
        if (pthread_create(&threads[i], NULL, worker, thread_id) != 0) {
            perror("Failed to create thread");
            return 1;
        }
    }

    for (int i = 0; i < NUM_THREADS * 100; i++) usys_yield();

    printf("Main thread is waiting for smc\n");
    usys_tee_wait_switch_req(&req);
    printf("Main thread is awaken from smc\n");

    if (0) {
        int ret;
        vaddr_t vaddr;
        vaddr = chcore_alloc_vaddr(PAGE_SIZE << 10);
        BUG_ON(vaddr == 0);
        ret = usys_map_tzasc_cma_meta(vaddr);
        BUG_ON(ret != 0);
        struct tzasc_cma_meta *tzasc_cma_meta = (struct tzasc_cma_meta *)vaddr;
        printf("%s %d base %#lx size %#lx\n", __func__, __LINE__, tzasc_cma_meta->base, tzasc_cma_meta->size);

        req.x1 = SMC_EXIT_SHADOW;
        req.x2 = 1;
        req.x3 = 16UL << 20;
        ret = usys_tee_switch_req(&req);
        printf("%s %d ret %d count %#lx\n", __func__, __LINE__, ret, tzasc_cma_meta->count);

        req.x1 = SMC_EXIT_SHADOW;
        req.x2 = 0;
        ret = usys_tee_switch_req(&req);
        printf("%s %d ret %d count %#lx\n", __func__, __LINE__, ret, tzasc_cma_meta->count);
        req.x1 = SMC_EXIT_SHADOW;
        req.x2 = 0;
        ret = usys_tee_switch_req(&req);
        printf("%s %d ret %d count %#lx\n", __func__, __LINE__, ret, tzasc_cma_meta->count);

        while (1);
    }

    pthread_create(&loop_thread, NULL, loop, NULL);
    printf("chanmgr: create rknpu\n");
    char *rknpu_argv[] = { "/rknpu.srv", "32", "32", "32" };
    pid_t pid = create_process(4, &rknpu_argv, NULL);
    int ret = waitpid(pid, NULL, 0);
    printf("chanmgr: rknpu test finish\n");

    // Wake up all threads
    pthread_mutex_lock(&mutex);
    printf("Main thread broadcasting to all workers.\n");
    pthread_cond_broadcast(&cond_var);
    pthread_mutex_unlock(&mutex);

    // Wait for all threads to finish
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    // Destroy mutex and condition variable
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond_var);

    BUG_ON(1);

    return 0;
}


struct all_ring_buffer_header {
    char io_model_path[256];
    char cache_p[256];
    char inner_model_path[256];
    char prompt[256];
    char n[256];
};

int main(void)
{
    int ret;

    for (int i = 0; i < 16; i++) {
        pthread_t t;
        if (pthread_create(&t, NULL, idle, NULL) != 0) {
            perror("Failed to create thread");
            return 1;
        }
        usys_yield(); usys_yield(); usys_yield(); usys_yield(); usys_yield(); usys_yield();
    }

    if (0) {

        printf("%s %d\n", __func__, __LINE__);
        usys_config_tzasc(8, 0x100000000UL >> 20, 0x140000000UL >> 20);
        usys_config_tzasc(8, 0x140000000UL >> 20, 0x140000000UL >> 20);
        printf("%s %d\n", __func__, __LINE__);

        // return 0;
    }

    if (1) {
        char *argv[] = {
            "llama-cli",
            "-m", "Meta-Llama-3-8B-Instruct.Q8_0-meta.gguf",
            // "-m", task_queue->inner_model_path,
            "--no-warmup",
            // "--file", "question.txt",
            // "-p", "hello",
            "-p", "llama#384",
            // "-p", task_queue->prompt,
            "--cache", "0",
            // "--cache", task_queue->cache_p,
            // "--tee-shm-paddr", tee_shm_paddr,
            "-n", "64",
            // "-n", task_queue->n,
            "-s", "123",
            // "-ngl", "100",
            "-t", "4",
            "-c", "1124",
            "--no-mmap"
        };
        char argc = sizeof(argv) / sizeof(*argv);
        printf("%s %d: launching llama\n", __func__, __LINE__);
        pid_t pid = create_process(argc, argv, NULL);
        int ret = waitpid(pid, NULL, 0);

        printf("%s %d: llama.cpp finished\n", __func__, __LINE__);
        if (0) {
            
            struct smc_registers req = {0};
            req.x1 = SMC_EXIT_SHADOW;
            req.x2 = 0xdeadbeef;
            int ret = usys_tee_switch_req(&req);
            BUG_ON(ret);
        }
        usys_top(0);
        while (1);

        return 0;
    }

    master();

    return 0;

    chanmgr_init();

    ret = ipc_register_server_with_destructor(
        chanmgr_dispatch, DEFAULT_CLIENT_REGISTER_HANDLER, chanmgr_destructor);
    printf("[chanmgr] register server value = %d\n", ret);

    usys_exit(0);
}
