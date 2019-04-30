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

#include <pthread.h>
#include "nstack.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include "nstack_eventpoll.h"
#include "nstack_socket.h"
#include "nstack_securec.h"
#include "nsfw_init_api.h"
#include "nstack_share_res.h"
#include "nsfw_mgr_com_api.h"
#include "nsfw_ps_mem_api.h"
#include "nsfw_ps_api.h"
#include "nsfw_recycle_api.h"
#include "nsfw_maintain_api.h"
#include "nstack_fd_mng.h"
#include "nstack_sem.h"
#include "nsfw_maintain_api.h"
#include "nstack_module.h"
#include "nsfw_mem_api.h"
#include "dmm_rwlock.h"
#include "nsfw_base_linux_api.h"
#include "nstack_dmm_dfx.h"
#include "nstack_info_parse.h"
#include "nstack_rd.h"

int nstack_dmm_dfx_init(nstack_proc_ops * ops);
nStack_info_t g_nStackInfo = {
    .hasInited = NSTACK_MODULE_INIT,
    .fwInited = NSTACK_MODULE_INIT,
    .init_mutex = PTHREAD_MUTEX_INITIALIZER,
    .lk_sockPool = NULL,
#ifndef KERNEL_FD_SUPPORT
    .fdhead = 0,
    .fdlock = {0},
#endif
    .pid = 0,
    .fork_lock = {0},
    .ikernelfdmax = NSTACK_MAX_SOCK_NUM,
};

int nstack_timeval2msec(struct timeval *pTime, long *msec)
{
    if (pTime->tv_sec < 0 || pTime->tv_usec < 0)
    {
        NSSOC_LOGERR("time->tv_sec is nagative");
        return -1;
    }

    if (NSTACK_MAX_U64_NUM / 1000 < (u64_t) pTime->tv_sec)
    {
        NSSOC_LOGERR("tout.tv_sec is too large]tout.tv_sec=%ld",
                     pTime->tv_sec);
        return -1;
    }
    long sec2msec = 1000 * pTime->tv_sec;
    long usec2msec = pTime->tv_usec / 1000;

    if (NSTACK_MAX_U64_NUM - sec2msec < usec2msec)
    {
        NSSOC_LOGERR
            ("nsec2msec plus sec2usec is too large]usec2msec=%lu,usec2msec=%lu",
             usec2msec, sec2msec);
        return -1;
    }

    *msec = sec2msec + usec2msec;
    return 0;
}

int nstack_current_time2msec(long *msec)
{
    struct timespec tout;
    if (unlikely(0 != clock_gettime(CLOCK_MONOTONIC, &tout)))
    {
        NSSOC_LOGERR("Failed to get time, errno=%d", errno);
    }

    if (NSTACK_MAX_U64_NUM / 1000 < (u64_t) tout.tv_sec)
    {
        NSSOC_LOGERR("tout.tv_sec is too large]tout.tv_sec=%ld", tout.tv_sec);
        return -1;
    }
    long sec2msec = 1000 * tout.tv_sec;
    long nsec2msec = tout.tv_nsec / 1000000;

    if (NSTACK_MAX_U64_NUM - sec2msec < nsec2msec)
    {
        NSSOC_LOGERR
            ("nsec2msec plus sec2usec is too large]nsec2msec=%lu,usec2msec=%lu",
             nsec2msec, sec2msec);
        return -1;
    }

    *msec = sec2msec + nsec2msec;

    return 0;
}

/*epoll and select shouldnot get affected by system time change*/
int nstack_sem_timedwait(sem_t * pSem, long abs_timeout /*ms */ ,
                         long *mcost)
{
    int retVal;

    /* clock_gettime() get second variable is long, so here should use long */
    long starttime, endtime;

#define FAST_SLEEP_TIME 10000
#define SLOW_SLEEP_TIME 500000
#define FAST_RETRY_COUNT 100
    unsigned int retry_count = 0;

    if (abs_timeout < 0 || nstack_current_time2msec(&starttime))
    {
        NSSOC_LOGERR("times out");
        errno = ETIMEDOUT;
        return -1;
    }

    while (1)
    {
        retVal = sem_trywait(pSem);

        if (nstack_current_time2msec(&endtime))
        {
            errno = ETIMEDOUT;
            return -1;
        }

        /*when get event we return the time cost */
        if (retVal == 0)
        {
            *mcost = (endtime - starttime);
            return 0;
        }
        /*when time out it return 0 */
        if (endtime < starttime || (endtime - starttime) > abs_timeout)
        {
            errno = ETIMEDOUT;
            *mcost = abs_timeout;
            return 0;
        }

        /*app calling setsockopt to set time */
        if (retry_count < FAST_RETRY_COUNT)
        {
            sys_sleep_ns(0, FAST_SLEEP_TIME);
            retry_count++;
        }
        else
        {
            sys_sleep_ns(0, SLOW_SLEEP_TIME);
        }
    }

}

NSTACK_STATIC inline char *get_ver_head(char *version)
{
    const char *split = " ";
    char *tmp = NULL;
    char *next_pos = NULL;

    tmp = strtok_s(version, split, &next_pos);
#ifndef SYSTEMC_LIB
    if (NULL == tmp || NULL == next_pos)
#else
    if (NULL == tmp)
#endif
    {
        return NULL;
    }

    // version
    tmp = strtok_s(next_pos, split, &next_pos);
    if (NULL == tmp)
    {
        return NULL;
    }

    return tmp;
}

NSTACK_STATIC int match_version(char *nstack_ver, char *my_ver)
{
    if ((NULL == nstack_ver || 0 == nstack_ver[0]) ||
        (NULL == my_ver || 0 == my_ver[0]))
    {
        NSSOC_LOGERR("invalid input]");
        return 0;
    }

    char *nstack_ver_head = NULL;
    char *my_ver_head = NULL;

    char nstack_version[NSTACK_VERSION_LEN] = { 0 };
    char my_version[NSTACK_VERSION_LEN] = { 0 };

    // !!!strtok_s will modify the original string, so use use temp for parameter
    /*use strcpy_s instead of memcpy_s to avoid invalid memory visit */
    if (EOK != strcpy_s(nstack_version, sizeof(nstack_version), nstack_ver))
    {
        return 0;
    }

    nstack_ver_head = get_ver_head(nstack_version);
    if (NULL == nstack_ver_head)
    {
        return 0;
    }

    /*use strcpy_s instead of memcpy_s to avoid invalid memory visit */
    if (EOK != strcpy_s(my_version, sizeof(my_version), my_ver))
    {
        return 0;
    }

    my_ver_head = get_ver_head(my_version);
    if (NULL == my_ver_head)
    {
        return 0;
    }

    /* Out-of-Bounds Read (FORTIFY.Out-of-Bounds_Read) */
    if (strlen(my_ver_head) != strlen(nstack_ver_head))
    {
        /*should return 0 when failed */
        return 0;
    }

    if (0 != strncmp(nstack_ver_head, my_ver_head, strlen(nstack_ver_head)))    /* Out-of-Bounds Read (FORTIFY.Out-of-Bounds_Read) */
    {
        return 0;
    }

    return 1;
}

NSTACK_STATIC inline void set_unmatch_version(char *version,
                                              unmatch_ver_info_t *
                                              app_ver_info)
{
    int i = 0;
    if (version == NULL || app_ver_info == NULL)
    {
        return;
    }

    for (; i < MAX_UNMATCH_VER_CNT; i++)
    {
        if (app_ver_info[i].unmatch_count != 0)
        {
            if (0 ==
                strncmp(version, app_ver_info[i].lib_version,
                        NSTACK_VERSION_LEN - 1))
            {
                app_ver_info[i].unmatch_count++;
                return;
            }
        }
        else
        {
            /* (1) use some fixed value but no effect  (e506) (2) it don't contain any extra commas (e505) */
            if (__sync_bool_compare_and_swap
                (&app_ver_info[i].unmatch_count, 0, 1))
            {
                // use strncpy_s to instead the complex logic
                //if version is too long, truncate it to ensure the copy success. so set 'count' to NSTACK_VERSION_LEN-1
                int retval = strncpy_s(app_ver_info[i].lib_version,
                                       NSTACK_VERSION_LEN, version,
                                       NSTACK_VERSION_LEN - 1);
                if (EOK != retval)
                {
                    NSSOC_LOGERR("strncpy_s failed]ret=%d", retval);
                    return;
                }

                get_current_time(app_ver_info[i].first_time_stamp,
                                 LOG_TIME_STAMP_LEN);
                return;
            }
        }
    }
}

NSTACK_STATIC inline int check_main_version()
{
    char my_version[NSTACK_VERSION_LEN] = { 0 };
    nsfw_mem_name stname =
        { NSFW_SHMEM, NSFW_PROC_MAIN, {NSTACK_VERSION_SHM} };
    g_nStackInfo.nstack_version = nsfw_mem_zone_lookup(&stname);

    if (NULL == g_nStackInfo.nstack_version)
    {
        NSSOC_LOGERR("can not get nstack version.");
        return 0;
    }

    /* copy string should use strcpy_s */
    if (EOK != strcpy_s(my_version, sizeof(my_version), NSTACK_VERSION))
    {
        NSSOC_LOGERR("strcpy_s failed");
        return 0;
    }

    if (match_version(g_nStackInfo.nstack_version, my_version))
    {
        return 1;
    }

    NSSOC_LOGERR("version not match]my version=%s, daemon-stack_version=%s",
                 my_version, g_nStackInfo.nstack_version);

    /* record unmatched app version in snapshot- */
    char *unmatch_app_version =
        g_nStackInfo.nstack_version + NSTACK_VERSION_LEN;

    set_unmatch_version(my_version,
                        (unmatch_ver_info_t *) unmatch_app_version);

    return 0;
}

int nstack_init_shmem()
{
    int deploytype = nstack_get_deploy_type();

    if ((deploytype != NSTACK_MODEL_TYPE1)
        && (deploytype != NSTACK_MODEL_TYPE_SIMPLE_STACK))
    {
        if (nstack_attach_share_res() != 0)
        {
            return -1;
        }

        if (-1 == nsep_attach_memory())
        {
            return -1;
        }

        if (-1 == ns_sync_sem_module_init(1, 0))
        {
            return -1;
        }
    }
    else
    {
        if (nstack_init_share_res() != 0)
        {
            return -1;
        }

        if (-1 == nsep_create_memory())
        {
            return -1;
        }

        if (-1 == ns_sync_sem_module_init(0, 0))
        {
            return -1;
        }
    }

    return 0;
}

/**
 *  This should be called only once
 */
NSTACK_STATIC int nstack_init_mem(void)
{
    int ret = ns_fail;
    int deploytype = nstack_get_deploy_type();

    /* record unmatched app version- */
    /* check lib version match - */
    if ((!check_main_version()) && (deploytype != NSTACK_MODEL_TYPE1)
        && (deploytype != NSTACK_MODEL_TYPE_SIMPLE_STACK))
    {
        NSSOC_LOGERR("check version failed");
        return ns_fail;
    }

    ret = nstack_init_shmem();
    if (ns_success != ret)
    {
        NSSOC_LOGERR("nstack init shmem fail");
        return ns_fail;
    }

    if (nstack_stack_module_init())
    {
        NSSOC_LOGERR("module init failed!");
        goto INIT_NOT_DONE;
    }

    if (ns_success != nstack_rd_sys())
    {
        NSSOC_LOGERR("nstack rd sys fail");
        return ns_fail;
    }
    /*init select mod */
    if (FALSE == select_module_init())
    {
        goto INIT_NOT_DONE;
    }
    if (nstack_dmm_dfx_init(nstack_fd_deal))
    {
        goto INIT_NOT_DONE;
    }
    ret = ns_success;
    /* The memory of the g_nStackInfo.lk_sockPool  was not released in the exception */
    return ret;
  INIT_NOT_DONE:
    ret = ns_fail;
    return ret;

}

void nstack_fork_fd_local_lock_info(nstack_fd_local_lock_info_t * local_lock)
{
    if (local_lock->fd_ref.counter > 1) /* after fork, if fd ref > 1, need set it to 1 */
    {
        local_lock->fd_ref.counter = 1;
    }
    dmm_spin_init(&local_lock->close_lock);
}

void nstack_reset_fd_local_lock_info(nstack_fd_local_lock_info_t * local_lock)
{
    atomic_set(&local_lock->fd_ref, 0);
    dmm_spin_init(&local_lock->close_lock);
    local_lock->fd_status = FD_CLOSE;
}

dmm_rwlock_t *get_fork_lock()
{
    return &g_nStackInfo.fork_lock;
}

NSTACK_STATIC int nstack_init_fd_local_info()
{
    int iindex = 0;
    int ret;
    nstack_fd_Inf *fdInf;

    g_nStackInfo.lk_sockPool = (nstack_fd_Inf *) malloc(NSTACK_KERNEL_FD_MAX * sizeof(nstack_fd_Inf));  /*malloc can be used */
    if (!g_nStackInfo.lk_sockPool)
    {
        NSSOC_LOGERR("malloc nstack_fd_lock_info failed");
        return ns_fail;
    }
    ret =
        memset_s(g_nStackInfo.lk_sockPool,
                 NSTACK_KERNEL_FD_MAX * sizeof(nstack_fd_Inf), 0,
                 NSTACK_KERNEL_FD_MAX * sizeof(nstack_fd_Inf));
    if (EOK != ret)
    {
        NSSOC_LOGERR("memset error");
        free(g_nStackInfo.lk_sockPool); /*free can be used */
        g_nStackInfo.lk_sockPool = NULL;
        return ns_fail;
    }

    for (iindex = 0; iindex < (int) NSTACK_KERNEL_FD_MAX; iindex++)
    {
        fdInf = &g_nStackInfo.lk_sockPool[iindex];
        nstack_reset_fd_inf(fdInf);
#ifndef KERNEL_FD_SUPPORT
        fdInf->fd = iindex;
        if (iindex == NSTACK_KERNEL_FD_MAX - 1)
        {
            fdInf->nxtfd = -1;
        }
        else
        {
            fdInf->nxtfd = iindex + 1;
        }
#endif
    }

#ifndef KERNEL_FD_SUPPORT
    g_nStackInfo.fdhead = 0;
    dmm_spin_init((dmm_spinlock_t *) & g_nStackInfo.fdlock);
#endif

    if (-1 ==
        nsep_init_info_sock_map(NSTACK_KERNEL_FD_MAX, NSTACK_MAX_MODULE_NUM))
    {
        NSSOC_LOGERR("malloc epInfoPool fail");
        if (g_nStackInfo.lk_sockPool)
        {
            free(g_nStackInfo.lk_sockPool);
            g_nStackInfo.lk_sockPool = NULL;
        }
        return ns_fail;
    }

    return ns_success;
}

/*=========== get share config for app =============*/

NSTACK_STATIC inline int get_share_config()
{
    static nsfw_mem_name g_cfg_mem_info =
        { NSFW_SHMEM, NSFW_PROC_MAIN, NSTACK_SHARE_CONFIG };
    int deploytype = nstack_get_deploy_type();

    if ((deploytype == NSTACK_MODEL_TYPE1)
        || (deploytype == NSTACK_MODEL_TYPE_SIMPLE_STACK))
    {
        get_default_base_cfg(1);
        return 0;
    }

    mzone_handle base_cfg_mem = nsfw_mem_zone_lookup(&g_cfg_mem_info);
    if (NULL == base_cfg_mem)
    {
        NSSOC_LOGERR("get config share mem failed.");
        return -1;
    }

    if (get_share_cfg_from_mem(base_cfg_mem) < 0)
    {
        NSSOC_LOGERR("get share config failed.");
        return -1;
    }

    NSSOC_LOGDBG("get share config success.");
    return 0;
}

/*design ensures that g_ksInfo is not write accessed at the same time.
  only read is done simultaneously with no chance of other thread writing it.
  so no protection needed.*/
int nstack_stack_init(void)
{
    // Just need to create shared memory
    int ret;

    /* log add start. */
    ret = nstack_init_fd_local_info();
    if (ret != ns_success)
    {
        goto INIT_DONE;
    }

    if (ns_fail == nstack_init_mem())
    {
        ret = ns_fail;
        goto INIT_DONE;
    }

    if (SYS_HOST_INITIAL_PID == get_sys_pid())
    {
        ret = ns_fail;
        goto INIT_DONE;
    }

    ret = ns_success;

#ifdef KERNEL_FD_SUPPORT
    nsep_get_manager()->checkEpollFD = nsfw_base_epoll_create(1);
#endif

  INIT_DONE:

    if (ns_success == ret)
    {
        NSSOC_LOGDBG("success");
    }
    else
    {
        NSSOC_LOGERR("fail");
    }
    return ret;
}

int nstack_for_epoll_init()
{
    NSSOC_LOGINF("fork] init begin..");
    if (g_nStackInfo.pid != 0 && g_nStackInfo.pid != getpid())
    {
        NSSOC_LOGINF("fork]g_nStackInfo.pid=%u,getpid=%d", g_nStackInfo.pid,
                     getpid());

        nstack_register_module_forchild();
    }
    return 0;
}

void signal_handler_app(int s)
{
    NSPOL_LOGERR("Received signal exiting.]s=%d", s);
    if (SIGHUP != s && SIGTERM != s)
    {
        nstack_segment_error(s);
    }
}

void register_signal_handler_app()
{
    /* signal handle function should comply secure coding standard
       here mask signal that will use in  sigwait() */
    sigset_t waitset, oset;
    if (0 != sigemptyset(&waitset))
    {
        NSPOL_LOGERR("sigemptyset failed");
    }
    if (0 != sigaddset(&waitset, SIGRTMIN))     /* for timer */
    {
        NSPOL_LOGERR("sigaddset failed");
    }
    if (0 != sigaddset(&waitset, SIGRTMIN + 2))
    {
        NSPOL_LOGERR("sigaddset failed");
    }
    if (0 != pthread_sigmask(SIG_BLOCK, &waitset, &oset))
    {
        NSPOL_LOGERR("pthread_sigmask failed");
    }

    struct sigaction s;
    s.sa_handler = signal_handler_app;
    if (0 != sigemptyset(&s.sa_mask))
    {
        NSPOL_LOGERR("sigemptyset failed.");
    }

    s.sa_flags = (int) SA_RESETHAND;

    /*register sig handler for more signals [start] */
    if (sigaction(SIGINT, &s, NULL) != 0)
    {
        NSPOL_LOGERR("Could not register SIGINT signal handler.");
    }
    if (sigaction(SIGSEGV, &s, NULL) != 0)
    {
        NSPOL_LOGERR("Could not register SIGSEGV signal handler.");
    }
    if (sigaction(SIGPIPE, &s, NULL) != 0)
    {
        NSPOL_LOGERR("Could not register SIGPIPE signal handler.");
    }
    if (sigaction(SIGFPE, &s, NULL) != 0)
    {
        NSPOL_LOGERR("Could not register SIGFPE signal handler.");
    }
    if (sigaction(SIGABRT, &s, NULL) != 0)
    {
        NSPOL_LOGERR("Could not register SIGABRT signal handler.");
    }
    if (sigaction(SIGBUS, &s, NULL) != 0)
    {
        NSPOL_LOGERR("Could not register SIGBUS signal handler.");
    }
    /*register sig handler for more signals [end] */

}

/*app send its version info to daemon-stack*/
/* when an app init finish, register its version to daemon-stack, daemon-stack will record it */
void nstack_app_touch(void)
{
    int i;
    for (i = 0; i < NSTACK_MAX_MODULE_NUM; i++)
    {
        if (nstack_fd_deal[i].app_touch)
        {
            nstack_fd_deal[i].app_touch();
        }
    }
}

int nstack_stack_module_load()
{
    if (0 != nstack_module_parse())
    {
        NSSOC_LOGERR("parse module config failed!");
        goto LOAD_FAIL;
    }
    if (0 != nstack_register_module())
    {
        NSSOC_LOGERR("register modules failed, fallback to default one");
        goto LOAD_FAIL;
    }
    return 0;

  LOAD_FAIL:
    return -1;
}

int nstack_app_init(void *ppara)
{
    NSSOC_LOGINF("nstack app init begin");

    if (get_share_config() < 0)
    {
        NSSOC_LOGERR("get share config failed");
        return ns_fail;
    }

    if (g_nStackInfo.pid != 0 && g_nStackInfo.pid != getpid())
    {
        NSSOC_LOGINF("fork]g_nStackInfo.pid=%u,getpid=%d", g_nStackInfo.pid,
                     getpid());
        nstack_register_module_forchild();
    }
#ifdef KERNEL_FD_SUPPORT
    long sysfdmax = 0;
    sysfdmax = sysconf(_SC_OPEN_MAX);
    NSSOC_LOGINF("sys max open files:%ld", sysfdmax);
    if (sysfdmax > 0)
    {
        g_nStackInfo.ikernelfdmax =
            (uint32_t) ((sysfdmax <=
                         ((NSTACK_MAX_SOCK_NUM / 8) *
                          60)) ? sysfdmax : ((NSTACK_MAX_SOCK_NUM / 8) * 60));
    }
    else
    {
        NSSOC_LOGERR("get sys max open file fail");
        g_nStackInfo.ikernelfdmax = NSTACK_MAX_SOCK_NUM;
    }
#endif
    NSSOC_LOGINF("final max fd:%u", g_nStackInfo.ikernelfdmax);

    nstack_set_maxfd_id(nstack_get_linux_mid(), g_nStackInfo.ikernelfdmax);

    g_nStackInfo.pid = getpid();

    /*if init already, just return success, if init fail before, just return err */
    if (NSTACK_MODULE_INIT != g_nStackInfo.hasInited)
    {
        NSSOC_LOGINF("nstack app already init state:%d",
                     g_nStackInfo.hasInited);
        return (NSTACK_MODULE_SUCCESS ==
                g_nStackInfo.hasInited ? ns_success : ns_fail);
    }

    if (0 != nstack_stack_init())
    {
        NSSOC_LOGERR("nstack stack init failed");
        g_nStackInfo.hasInited = NSTACK_MODULE_FAIL;
        return ns_fail;
    }

    nstack_app_touch();         /*app send its version info to daemon-stack */

    g_nStackInfo.hasInited = NSTACK_MODULE_SUCCESS;
    NSSOC_LOGINF("nstack app init success end");
    return ns_success;
}

int mem_adpt_init(void *handle, nsfw_mem_attr * mem_ops,
                  nsfw_ring_ops * ring_ops)
{
    int i = 0;
    nsfw_ring_ops *temp_ring_ops;

    mem_ops[NSFW_SHMEM].stmemop = dlsym(handle, "g_shmem_ops");
    mem_ops[NSFW_NSHMEM].stmemop = dlsym(handle, "g_nshmem_ops");
    temp_ring_ops = dlsym(handle, "g_ring_ops_arry_spl");

    for (i = 0; i < NSFW_MEM_TYPEMAX * NSFW_MPOOL_TYPEMAX; i++)
    {
        ring_ops[i] = *temp_ring_ops;
        temp_ring_ops++;
    }

    NSFW_LOGINF("get shmem and nshmem and ring_ops ops var success.");

    return 0;
}

/*nsocket call framework init fun*/
int nstack_fw_init()
{
    int ret = ns_fail;

    if (NSTACK_MODULE_SUCCESS == g_nStackInfo.fwInited)
    {
        return ns_success;
    }
    if (NSTACK_MODULE_INIT == g_nStackInfo.fwInited)
    {
        g_nStackInfo.fwInited = NSTACK_MODULE_INITING;
        nstack_log_init_app();
        if (0 != nstack_stack_module_load())
        {
            NSSOC_LOGERR("nstack stack module load failed!");
            g_nStackInfo.fwInited = NSTACK_MODULE_FAIL;
            return -1;
        }

        dmm_read_lock(get_fork_lock());
        updata_sys_pid();
        u8 proc_type = NSFW_PROC_APP;
        nsfw_mem_para stinfo = { 0 };
        stinfo.iargsnum = 0;
        stinfo.pargs = NULL;
        stinfo.enflag = (fw_poc_type) proc_type;

        nstack_framework_set_module_param(NSFW_MEM_MGR_MODULE,
                                          (void *) &stinfo);
        nstack_framework_set_module_param(NSFW_MGR_COM_MODULE,
                                          (void *) ((long long) proc_type));
        nstack_framework_set_module_param(NSFW_PS_MODULE,
                                          (void *) ((long long) proc_type));
        nstack_framework_set_module_param(NSFW_PS_MEM_MODULE,
                                          (void *) ((long long) proc_type));
        nstack_framework_set_module_param(NSFW_RECYCLE_MODULE,
                                          (void *) ((long long) proc_type));

        ret = nstack_framework_init();

        if (ns_success == ret)
        {
            g_nStackInfo.fwInited = NSTACK_MODULE_SUCCESS;
        }
        else
        {
            g_nStackInfo.fwInited = NSTACK_MODULE_FAIL;
        }
        dmm_read_unlock(get_fork_lock());
    }
    return ret;
}

nstack_fd_local_lock_info_t *get_fd_local_lock_info(int fd)
{
    if (!g_nStackInfo.lk_sockPool)
    {
        return NULL;
    }

    if (fd >= 0 && fd < (int) NSTACK_KERNEL_FD_MAX)
    {
        return &(g_nStackInfo.lk_sockPool[fd].local_lock);
    }

    return NULL;
}

int nstack_dmm_dfx_init(nstack_proc_ops * ops)
{
    int i;
    int ret;
    nstack_dmm_stack_ops_t dfx_ops[NSTACK_MAX_MODULE_NUM];

    if (!ops)
        return ns_fail;

    dmm_fd_dfx_pool = (nstack_fd_dfx_t *) malloc(NSTACK_KERNEL_FD_MAX * sizeof(nstack_fd_dfx_t));       /*malloc can be used */
    if (!dmm_fd_dfx_pool)
    {
        NSSOC_LOGERR("malloc fd_dfx_pool failed");
        free(g_nStackInfo.lk_sockPool);
        g_nStackInfo.lk_sockPool = NULL;
        return ns_fail;

    }
    else
    {
        ret =
            memset_s(dmm_fd_dfx_pool,
                     NSTACK_KERNEL_FD_MAX * sizeof(nstack_fd_dfx_t), 0,
                     NSTACK_KERNEL_FD_MAX * sizeof(nstack_fd_dfx_t));
        if (EOK != ret)
        {
            NSSOC_LOGERR("memset failed");
            free(g_nStackInfo.lk_sockPool);
            g_nStackInfo.lk_sockPool = NULL;
            free(dmm_fd_dfx_pool);
            dmm_fd_dfx_pool = NULL;
            return ns_fail;
        }
    }

    for (i = 0; i < NSTACK_MAX_MODULE_NUM; i++)
    {
        dfx_ops[i].get_stack_tick = ops[i].get_stack_tick;
        dfx_ops[i].update_dfx_data = ops[i].update_dfx_data;
        dfx_ops[i].type = 0;
    }

    return nstack_dfx_init_ops(dfx_ops);
}
