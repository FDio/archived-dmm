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

#ifndef __NSTACK_DMM_DFX_H__
#define __NSTACK_DMM_DFX_H__
#include <time.h>
#include "types.h"
#include "nsfw_dfx_api.h"
#include "nstack_callback_ops.h"

typedef struct nstack_fd_dfx_s
{
    u64 last_send_out_tick;
    u64 last_send_in_tick;
    u64 last_recv_out_tick;
    u64 last_recv_in_tick;
    int send_stat_count;
    int recv_stat_count;
} nstack_fd_dfx_t;

extern nstack_dmm_stack_ops_t *g_nstack_dmm_dfx_ops;

#define NSTACK_GET_SYS_TICK(data) if(g_nstack_dmm_dfx_ops && g_nstack_dmm_dfx_ops[0].get_stack_tick) g_nstack_dmm_dfx_ops[0].get_stack_tick(data);

#define NSTACK_FD_DFX_LAST_SEND_TICK_IN(fd, tick) \
if (dmm_fd_dfx_pool) \
{ \
    dmm_fd_dfx_pool[fd].last_send_in_tick = tick; \
    dmm_fd_dfx_pool[fd].send_stat_count++; \
    /* todo stat longest send */ \
}

#define NSTACK_FD_DFX_LAST_SEND_TICK_OUT(fd, tick) \
if (dmm_fd_dfx_pool) \
{ \
    dmm_fd_dfx_pool[fd].last_send_out_tick = tick; \
    /* todo stat longest send */ \
}

#define NSTACK_FD_DFX_LAST_RECV_TICK_IN(fd, tick) \
if (dmm_fd_dfx_pool) \
{ \
    dmm_fd_dfx_pool[fd].last_recv_in_tick = tick; \
    dmm_fd_dfx_pool[fd].recv_stat_count++; \
    /* todo stat longest send */ \
}

#define NSTACK_FD_DFX_LAST_RECV_TICK_OUT(fd, tick) \
if (dmm_fd_dfx_pool) \
{ \
    dmm_fd_dfx_pool[fd].last_recv_out_tick = tick; \
    /* todo stat longest send */ \
}

extern nstack_fd_dfx_t *dmm_fd_dfx_pool;
#endif
