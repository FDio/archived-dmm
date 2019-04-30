/*
*
* Copyright (c) 2018 Huawei Technologies Co.,Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at:
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef _NSTACK_H_
#define _NSTACK_H_

#include <sys/socket.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "nstack_log.h"
#include "nstack_module.h"
#include "nstack_fd_mng.h"

#include "types.h"
#include "nstack_eventpoll.h"
#include "nstack_select.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "nstack_atomic.h"
#include "nsfw_mem_api.h"
#include "nsfw_recycle_api.h"
#include "dmm_rwlock.h"

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C"{
/* *INDENT-ON* */
#endif

#define NSTACK_PIDINFO "hw_nstack_pidinfo"

typedef struct _dict_
{
    int n;
    ssize_t size;
    char **key;
    char **val;
    unsigned *hash;
} dict;
/* release sockets when app exit */
typedef struct
{
    uint32_t hostpid;
    uint32_t pid;
    uint64_t pidns;
    atomic_t socketCount;
} __attribute__ ((__packed__)) nStackPidInfo_t;

typedef enum
{
    NSTACK_MODULE_INIT,
    NSTACK_MODULE_INITING,
    NSTACK_MODULE_SUCCESS,
    NSTACK_MODULE_FAIL
} nstack_module_state;

typedef struct
{
    nstack_module_state hasInited;      /*nsocket inside init status */
    nstack_module_state fwInited;       /*framework init status */
    char pad1[2];

    pthread_mutex_t init_mutex;
    /* if a nstack_fd_Inf contains a valid linux kernel proFD, it will be allocated from this poll.
     * Total size of the poll is NSTACK_MAX_SOCK_NUM, index range is [0, NSTACK_MAX_SOCK_NUM).
     */
    nstack_fd_Inf *lk_sockPool;

#ifndef KERNEL_FD_SUPPORT
    int fdhead;
    dmm_spinlock_t fdlock;
#endif

    dmm_rwlock_t fork_lock;     /* to ensure that there is no fd to create and close when fork. */
    uint32_t pid;
    char *nstack_version;
    int checkEpollFD;
    uint32_t ikernelfdmax;
} __attribute__ ((__packed__)) nStack_info_t;

#define ENV_NSTACK_RD_CFG_PATH  "NSTACK_RD_CFG_PATH"

#define nstack_set_errno(no) errno = (no)

extern nStack_info_t g_nStackInfo;

#define NSTACK_KERNEL_FD_MAX (g_nStackInfo.ikernelfdmax)

#define nstack_each_protoFDSt(modInx, fdInf, st)  \
        for ((modInx) = 0; ((modInx) < nstack_get_module_num() && ((st) = nstack_get_proto_fd_st((fdInf), modInx))); (modInx)++)

extern int nstack_timeval2msec(struct timeval *pTime, long *msec);
extern int nstack_current_time2msec(long *msec);
extern int nstack_sem_timedwait(sem_t * pSem, long abs_timeout /*ms */ ,
                                long *mcost);
extern int nstack_app_init(void *ppara);
extern int nstack_fw_init();

nstack_fd_local_lock_info_t *get_fd_local_lock_info(int fd);
void nstack_fork_fd_local_lock_info(nstack_fd_local_lock_info_t * local_lock);
void nstack_reset_fd_local_lock_info(nstack_fd_local_lock_info_t *
                                     local_lock);
dmm_rwlock_t *get_fork_lock();
int nstack_for_epoll_init();

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif
