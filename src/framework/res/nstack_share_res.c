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

#include "nstack_share_res.h"
#include "nsfw_mem_api.h"
#include "types.h"
#include "nstack_securec.h"
#include "nstack_log.h"
#include "nsfw_maintain_api.h"

#include "nsfw_ps_api.h"

#define NSTACK_SHARE_RES "nstack_share_res"

#define MAX_DELAY_RECYCLE_SEC 15

typedef struct
{
    volatile u16 forking;
    u8 delay_recycle;
    u8 delay_tick;
    volatile u16 child_hbt;
    u16 old_child_hbt;
} nstack_fork_recycle;

typedef struct
{
    nstack_fork_recycle fork_recycle[NSFW_MAX_PID];
} nstack_share_res;

NSTACK_STATIC nstack_share_res *g_nstack_share_res;
NSTACK_STATIC volatile int g_enable_child_hbt = 0;

/*  Add dfx timer tick */
/** global timer tick */
u64 g_nstack_timer_init_value = 0;
nstack_tick_info_t g_nstack_timer_tick = {.tick_ptr =
        &g_nstack_timer_init_value,
};

int nstack_init_share_res()
{
    mzone_handle zone;
    nsfw_mem_zone param;
    int ret;

    param.isocket_id = -1;
    param.lenth = sizeof(nstack_share_res);
    param.stname.entype = NSFW_SHMEM;

    ret = strcpy_s(param.stname.aname, NSFW_MEM_NAME_LENTH, NSTACK_SHARE_RES);
    if (EOK != ret)
    {
        NSSOC_LOGERR("strcpy_s failed]name=%s,ret=%d", NSTACK_SHARE_RES, ret);
        return -1;
    }

    zone = nsfw_mem_zone_create(&param);
    if (!zone)
    {
        NSSOC_LOGERR("nsfw_mem_zone_create failed]name=%s", NSTACK_SHARE_RES);
        return -1;
    }

    g_nstack_share_res = (nstack_share_res *) zone;
    if (EOK !=
        memset_s(g_nstack_share_res, sizeof(nstack_share_res), 0,
                 sizeof(nstack_share_res)))
    {
        NSSOC_LOGERR("memset failed");
        return -1;
    }

    NSSOC_LOGDBG("ok");
    return 0;
}

NSTACK_STATIC int nstack_lookup_share_res()
{
    mzone_handle zone;
    nsfw_mem_name param;

    param.entype = NSFW_SHMEM;
    param.enowner = NSFW_PROC_MAIN;
    if (strcpy_s(param.aname, NSFW_MEM_NAME_LENTH, NSTACK_SHARE_RES) != 0)
    {
        NSSOC_LOGERR("strcpy_s failed]name=%s", NSTACK_SHARE_RES);
        return -1;
    }

    zone = nsfw_mem_zone_lookup(&param);
    if (!zone)
    {
        NSSOC_LOGERR("nsfw_mem_zone_lookup failed]name=%s", NSTACK_SHARE_RES);
        return -1;
    }

    g_nstack_share_res = (nstack_share_res *) zone;
    NSSOC_LOGDBG("ok");
    return 0;
}

/* Add dfx timer tick */
NSTACK_STATIC int nstack_lookup_share_global_tick()
{
    int ret;
    nsfw_mem_name name = {.entype = NSFW_SHMEM,.enowner = NSFW_PROC_MAIN };

    ret = strcpy_s(name.aname, NSFW_MEM_NAME_LENTH, NSTACK_GLOBAL_TICK_SHM);
    if (EOK != ret)
    {
        NSSOC_LOGERR("strcpy_s failed]name=%s,ret=%d",
                     NSTACK_GLOBAL_TICK_SHM, ret);
        return -1;
    }

    g_nstack_timer_tick.tick_ptr = (u64 *) nsfw_mem_zone_lookup(&name);
    if (NULL == g_nstack_timer_tick.tick_ptr)
    {
        NSSOC_LOGERR("Failed to lookup global timer tick memory");
        return -1;
    }

    NSSOC_LOGDBG("ok");
    return 0;
}

int nstack_attach_share_res()
{
    if (nstack_lookup_share_res() != 0)
    {
        return -1;
    }

    /* Add dfx timer tick */
    if (nstack_lookup_share_global_tick() != 0)
    {
        return -1;
    }

    return 0;
}

void fork_parent_start(i32 ppid)
{
    g_nstack_share_res->fork_recycle[ppid].forking = 1;
}

/*
 * if child die, child_hbt will stop changing, parent wait FORK_WAIT_SEC seconds.
 * otherwise, parent wait until child fork done.
 */
void fork_wait_child_done(u32 ppid)
{
#define FORK_WAIT_SEC 5
#define FORK_SLEEP_MS 10
#define FORK_WAIT_CNT (FORK_WAIT_SEC * 1000 / FORK_SLEEP_MS)
    u32 wait_cnt = FORK_WAIT_CNT;
    nstack_fork_recycle *recycle = &g_nstack_share_res->fork_recycle[ppid];
    while (recycle->forking && wait_cnt)
    {
        --wait_cnt;
        sys_sleep_ns(0, 1000000 * FORK_SLEEP_MS);

        if (recycle->old_child_hbt != recycle->child_hbt)
        {
            recycle->old_child_hbt = recycle->child_hbt;
            wait_cnt = FORK_WAIT_CNT;
        }
    }

    if ((0 == wait_cnt) && recycle->forking)
    {
        NSSOC_LOGWAR("timeout] waited time=%u,ppid=%u", FORK_WAIT_SEC, ppid);
        recycle->forking = 0;
    }
}

void fork_parent_failed(u32 ppid)
{
    g_nstack_share_res->fork_recycle[ppid].forking = 0;
}

NSTACK_STATIC void *fork_start_child_hbt(void *arg)
{
    u32 ppid = (u32) (u64) arg;
    nstack_fork_recycle *recycle = &g_nstack_share_res->fork_recycle[ppid];

    while (g_enable_child_hbt)
    {
        ++recycle->child_hbt;
        sys_sleep_ns(0, 10);
    }

    return NULL;
}

void fork_child_start(u32 ppid)
{
    g_enable_child_hbt = 1;
    pthread_t t;
    if (pthread_create(&t, NULL, fork_start_child_hbt, (void *) (u64) ppid))
    {
        NSPOL_LOGERR("pthread_create failed]ppid=%u", ppid);
    }
}

void fork_child_done(u32 ppid)
{
    g_enable_child_hbt = 0;
    g_nstack_share_res->fork_recycle[ppid].forking = 0;
}

int fork_recycle_check(u32 pid)
{
    if (g_nstack_share_res->fork_recycle[pid].forking)
    {
        g_nstack_share_res->fork_recycle[pid].delay_recycle = 1;
        return -1;
    }

    return 0;
}

/*
 * if child die, child_hbt will stop changing, daemon-stack delay MAX_DELAY_RECYCLE_SEC seconds to recycle.
 * otherwise, daemon-stack delay recycle until child fork done.
 */
void fork_delay_recycle(u8 sec, nsfw_recycle_fun fun)
{
    u32 i;

    for (i = 0; i < NSFW_MAX_PID; ++i)
    {
        nstack_fork_recycle *recycle = &g_nstack_share_res->fork_recycle[i];
        if (recycle->delay_recycle)
        {
            if (recycle->old_child_hbt != recycle->child_hbt)
            {
                recycle->old_child_hbt = recycle->child_hbt;
                recycle->delay_tick = 0;
            }
            else
            {
                recycle->delay_tick += sec;
                if (!recycle->forking
                    || (recycle->delay_tick > MAX_DELAY_RECYCLE_SEC))
                {
                    recycle->delay_recycle = 0;
                    recycle->delay_tick = 0;
                    recycle->forking = 0;
                    (void) fun(i, NULL, 0);
                }
            }
        }
    }
}
