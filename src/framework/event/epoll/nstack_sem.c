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

#include <errno.h>
#include "nstack_securec.h"
#include "types.h"
#include "nsfw_init_api.h"
#include "nsfw_maintain_api.h"
#include "nsfw_mgr_com_api.h"
#include "nsfw_mem_api.h"
#include "nstack_log.h"
#include "nstack_sem.h"
#include "nstack_epoll_api.h"

i32 ns_semphore_init(ns_sem_type_t * sem, i32 pshared, u32 value);
i32 ns_semphore_sem_timewait(ns_sem_type_t * sem, i32 timeout, u32 sleeptime);
i32 ns_semphore_sem_post(ns_sem_type_t * sem);
i32 ns_semphore_sem_destory(ns_sem_type_t * sem);
i32 ns_sysv_msg_init(ns_sem_type_t * sem, i32 pshared, u32 value);
i32 ns_sysv_msg_timewait(ns_sem_type_t * sem, i32 timeout, u32 sleeptime);      /* milliseconds */
i32 ns_sysv_msg_post(ns_sem_type_t * sem);
i32 ns_sysv_msg_destory(ns_sem_type_t * sem);

#define NS_SYNC_SEM_SHARED_ARGS_MAX_SIZE    1024
#define NS_SYNC_SEM_SHARED_MEM_NAME         "NSTACK_FW_NS_SYNC_SEM_SHARED"
#define NSFW_SYNC_SEM_MODULE        "nsfw_sync_sem"

typedef struct ns_sync_mem_ifno_s
{
    ns_sync_type_t mode;
    char parm[NS_SYNC_SEM_SHARED_ARGS_MAX_SIZE];
} ns_sync_mem_ifno_t;

ns_sync_sem_fun_t g_ns_sync_ops = {
    NULL,
    NULL,
    NULL,
    NULL
};

ns_sync_mem_ifno_t *g_sync_shared_args = NULL;

int sem_current_time2msec(u64 * msec)
{
#define SEM_MAX_U64_NUM ((u64)0xffffffffffffffff)

    struct timespec tout;

    if (0 != clock_gettime(CLOCK_MONOTONIC, &tout))
    {
        NSSOC_LOGERR("Failed to get time, errno = %d", errno);
    }

    if (SEM_MAX_U64_NUM / 1000 < (u64) tout.tv_sec)
    {
        NSSOC_LOGERR("tout.tv_sec is too large]tout.tv_sec=%ld", tout.tv_sec);
        return -1;
    }

    u64 sec2msec = 1000 * tout.tv_sec;
    u64 nsec2msec = (u64) tout.tv_nsec / 1000000;
    if (SEM_MAX_U64_NUM - sec2msec < nsec2msec)
    {
        NSSOC_LOGERR
            ("nsec2msec plus sec2usec is too large]nsec2msec=%llu,usec2msec=%llu",
             nsec2msec, sec2msec);
        return -1;
    }

    *msec = sec2msec + nsec2msec;

    return 0;
}

/*****************************************************************************
*   Prototype    : ns_sync_mem_create
*   Description  : create a share mem with nstack and app
*   Input        : ns_sync_mem_ifno_t **mem
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
mzone_handle ns_sync_mem_create(size_t size)
{
    nsfw_mem_zone pmeminfo;
    mzone_handle phandle;
    int ret;

    pmeminfo.ireserv = 0;
    pmeminfo.isocket_id = NSFW_SOCKET_ANY;
    pmeminfo.lenth = size;

    ret =
        strcpy_s(pmeminfo.stname.aname, sizeof(pmeminfo.stname.aname),
                 NS_SYNC_SEM_SHARED_MEM_NAME);
    if (EOK != ret)
    {
        NSSOC_LOGERR("strcpy_s failed]name=%s,ret=%d",
                     NS_SYNC_SEM_SHARED_MEM_NAME, ret);
        return NULL;
    }
    pmeminfo.stname.entype = NSFW_SHMEM;

    phandle = nsfw_mem_zone_create(&pmeminfo);
    if (NULL == phandle)
    {
        NSSOC_LOGERR("create nstack sync memory failed]name=%s",
                     NS_SYNC_SEM_SHARED_MEM_NAME);
        return NULL;
    }

    return phandle;

}

/*****************************************************************************
*   Prototype    : ns_sync_mem_lookup
*   Description  : app look up the shared mem ,create by nstack
*   Input        : ns_sync_mem_ifno_t **mem
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
mzone_handle ns_sync_mem_lookup(char *str)
{
    nsfw_mem_name name;

    name.entype = NSFW_SHMEM;
    name.enowner = NSFW_PROC_MAIN;
    mzone_handle phandle;

    if (-1 == sprintf_s(name.aname, NSFW_MEM_NAME_LENTH, "%s", str))
    {
        NSSOC_LOGERR("Error to attach sync]name=%s", str);
        return NULL;
    }

    phandle = nsfw_mem_zone_lookup(&name);
    if (NULL == phandle)
    {
        NSSOC_LOGERR("create nstack sync memory failed]name=%s", str);
        return NULL;
    }

    return phandle;
}

/*****************************************************************************
*   Prototype    : ns_sync_func_init
*   Description  : init function
*   Input        : u32 mode
*   Output       : None
*   Return Value : NSTACK_STATIC void
*   Calls        :
*   Called By    :
*****************************************************************************/
NSTACK_STATIC void ns_sync_func_init(u32 mode)
{
    switch (mode)
    {
        case NS_SYNC_SYSV_MSG:
            g_ns_sync_ops.ns_sync_sem_init = ns_sysv_msg_init;
            g_ns_sync_ops.ns_sync_sem_post = ns_sysv_msg_post;
            g_ns_sync_ops.ns_sync_sem_timedwait = ns_sysv_msg_timewait;
            g_ns_sync_ops.ns_sync_sem_destroy = ns_sysv_msg_destory;
            break;
        case NS_SYNC_SEM_TRY:
        default:
            g_ns_sync_ops.ns_sync_sem_init = ns_semphore_init;
            g_ns_sync_ops.ns_sync_sem_post = ns_semphore_sem_post;
            g_ns_sync_ops.ns_sync_sem_timedwait = ns_semphore_sem_timewait;
            g_ns_sync_ops.ns_sync_sem_destroy = ns_semphore_sem_destory;
            break;
    }

}

/*****************************************************************************
*   Prototype    : ns_sync_sem_module_init
*   Description  : read config file and shared mem
*   Input        : void * args
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 ns_sync_sem_module_init(int type, ns_sync_type_t mode)
{
    i32 ret = 0;

    switch (type)
    {

        case 0:
            g_sync_shared_args =
                ns_sync_mem_create(sizeof(ns_sync_mem_ifno_t));
            if (NULL == g_sync_shared_args)
            {
                NSFW_LOGERR("%s create share mem failed",
                            NSFW_SYNC_SEM_MODULE);
                ret = -1;
                break;
            }
            g_sync_shared_args->mode = mode;

            ns_sync_func_init(g_sync_shared_args->mode);
            break;
        case 1:
            g_sync_shared_args =
                ns_sync_mem_lookup(NS_SYNC_SEM_SHARED_MEM_NAME);
            if (NULL == g_sync_shared_args)
            {
                NSFW_LOGERR("%s lookup shared mem failed",
                            NSFW_SYNC_SEM_MODULE);
                ret = -1;
                break;
            }

            ns_sync_func_init(g_sync_shared_args->mode);
            break;
        default:
            if (type < NSFW_PROC_MAX)
            {
                NSFW_LOGERR("%s outof type", NSFW_SYNC_SEM_MODULE);
                break;
            }
            ret = -1;
    }

    NSFW_LOGDBG("%s init ret = %d", NSFW_SYNC_SEM_MODULE, ret);
    return ret;
}

/****************************************************************/

/* semaphore mode functions*/
i32 ns_semphore_init(ns_sem_type_t * sem, i32 pshared, u32 value)
{
    return sem_init(&sem->semphore, pshared, value);
}

/*****************************************************************************
*   Prototype    : ns_semphore_sem_timewait
*   Description  : semaphore wait
*   Input        : ns_sem_type_t *sem
*                  i32 timeout    used ms, block if < 0
*                  u32 sleeptime  if timeout > 0, and sleeptime > 0 used sleep(sleeptime) and try agin
*                  ns_sem_process_type_t type
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 ns_semphore_sem_timewait(ns_sem_type_t * sem, i32 timeout, u32 sleeptime)
{
#define         FAST_SLEEP_TIME 10000
#define         SLOW_SLEEP_TIME 500000
#define         FAST_RETRY_COUNT 100

    i32 retVal = 0;
    u64 starttime;
    u64 endtime;
    u32 retry_count = 0;

    /* trywait */
    if (timeout == 0)
    {
        return sem_trywait(&sem->semphore);
    }

    /* block when no event recv */
    if (timeout < 0)
    {
        return sem_wait(&sem->semphore);
    }

    /* for timeout */
    if (sem_current_time2msec(&starttime))
    {
        errno = ETIMEDOUT;
        return -1;
    }
    while (1)
    {
        retVal = sem_trywait(&sem->semphore);

        if (retVal == 0)
        {
            break;
        }

        if (sem_current_time2msec(&endtime))
        {
            errno = ETIMEDOUT;
            return -1;
        }

        if (endtime < starttime || (endtime - starttime) > timeout)
        {
            errno = ETIMEDOUT;
            return -1;
        }

        /*app calling setsockopt to set  time */
        if (sleeptime > 0)
        {
            long wait_sec;
            long wait_nsec;
            wait_sec = sleeptime / 1000000;
            wait_nsec = 1000 * (sleeptime % 1000000);
            sys_sleep_ns(wait_sec, wait_nsec);  //g_sem_sleep_time
        }
        else if (retry_count < FAST_RETRY_COUNT)
        {
            sys_sleep_ns(0, FAST_SLEEP_TIME);
            retry_count++;
        }
        else
        {
            sys_sleep_ns(0, SLOW_SLEEP_TIME);
        }
    }

    return retVal;

}

/* semaphore post */
i32 ns_semphore_sem_post(ns_sem_type_t * sem)
{
    return sem_post(&sem->semphore);
}

/*semaphore destory*/
i32 ns_semphore_sem_destory(ns_sem_type_t * sem)
{
    return sem_destroy(&sem->semphore);
}

/*****************************************************************************
*   Prototype    : ns_sysv_msg_init
*   Description  : init a system V msg
*   Input        : ns_sem_type_t *sem
*                  u32 pshared
*                  u32 value
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 ns_sysv_msg_init(ns_sem_type_t * sem, i32 pshared, u32 value)
{
#define KEY_START       30000

    unsigned short semInit = 0;
    key_t key;
    u32 *args;

    args = (u32 *) sem->args;
    value = *args;
    key = KEY_START + value;
    sem->sysv.key = key;
    sem->sysv.sock_id = semget(key, 1, IPC_CREAT | 0660);
    sem->sysv.stack_id = -1;

    semctl(sem->sysv.sock_id, 0, SETALL, &semInit);

    return 0;
}

/* system V timewait */
i32 ns_sysv_msg_timewait(ns_sem_type_t * sem, i32 timeout, u32 sleeptime)       /* milliseconds */
{
    struct timespec tmout;
    struct sembuf operations = { 0, -1, 0 };
    int id;

    id = semget(sem->sysv.key, 1, 0660);
    if (-1 == id)
    {
        errno = EIDRM;
        return -1;
    }

    if (timeout < 0)
    {
        return semop(id, &operations, 1);
    }

    tmout.tv_sec = timeout / 1000;
    tmout.tv_nsec = (timeout % 1000) * 1000 * 1000;
    return semtimedop(id, &operations, 1, &tmout);
}

/* system V post */
i32 ns_sysv_msg_post(ns_sem_type_t * sem)
{
    struct sembuf operations = { 0, 1, 0 };
    int id;

    id = semget(sem->sysv.key, 1, 0660);
    if (-1 == id)
    {
        errno = EIDRM;
        return -1;
    }

    return semop(id, &operations, 1);
}

/* destory system V msg */
i32 ns_sysv_msg_destory(ns_sem_type_t * sem)
{
    key_t key;

    key = semget(sem->sysv.key, 1, 0660);
    return semctl(key, 0, IPC_RMID);
}
