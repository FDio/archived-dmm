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

#ifndef NSTACK_SHARE_RES_H
#define NSTACK_SHARE_RES_H

#include "nstack_log.h"
#include "compiling_check.h"
#include "nsfw_recycle_api.h"

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
#endif

#define NSTACK_VERSION_SHM "nstack_version"
#define MAX_U16_INT 0xFFFF
#define NSTACK_VERSION_LEN 128

COMPAT_PROTECT_RETURN(NSTACK_VERSION_LEN, 128);
#define MAX_UNMATCH_VER_CNT 32
COMPAT_PROTECT_RETURN(MAX_UNMATCH_VER_CNT, 32);

/* Add dfx timer tick */
#define NSTACK_GLOBAL_TICK_SHM "nstack_global_tick"

typedef struct unmatch_ver_info
{
    int unmatch_count;
    char lib_version[NSTACK_VERSION_LEN];
    char first_time_stamp[LOG_TIME_STAMP_LEN];
} unmatch_ver_info_t;

/* Add dfx timer tick Begin */
#define DFX_TMR_INTERVAL 60000  /*60 seconds */
typedef struct nstack_tick_info
{
    u64 *tick_ptr;              // tick from shared memory
    u64 interval;               // tick interval, only used in stack process
    /* tick refference, updated periodically and read in tcpip_thread only */
    struct timeval ref_time;    // ref tick time
    u64 ref_tick;               // ref tick
} nstack_tick_info_t;
/* Add dfx timer tick End */

int nstack_init_share_res();
int nstack_attach_share_res();

void fork_parent_start(i32 ppid);
void fork_wait_child_done(u32 ppid);
void fork_parent_failed(u32 ppid);
void fork_child_start(u32 ppid);
void fork_child_done(u32 ppid);
int fork_recycle_check(u32 pid);
void fork_delay_recycle(u8 sec, nsfw_recycle_fun fun);

static inline u16 calculate_elapse(u64 a, u64 b)
{
    u64 ret = 0;
    if (a > b)
    {
        ret = a - b;
        return ret < MAX_U16_INT ? (u16) ret : (u16) MAX_U16_INT;
    }
    else
    {
        return 0;
    }
}

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif
