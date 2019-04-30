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

#include "nstack_dmm_dfx.h"
#include "nstack_securec.h"
#include "nstack_module.h"
#include "nstack_log.h"

nstack_dmm_stack_ops_t *g_nstack_dmm_dfx_ops;

#define nstack_dfx_calculate_elapse(a, b) ((a)>(b)?((((a)-(b))<0XFFFF)?(a)-(b):0XFFFF): 0)
nstack_fd_dfx_t *dmm_fd_dfx_pool = NULL;

void nstack_dfx_state_update(u64 fd, int midx, nstack_dmm_type_t type,
                             void *data)
{
    if (midx < 0 ||
        !g_nstack_dmm_dfx_ops ||
        !(g_nstack_dmm_dfx_ops[midx].update_dfx_data))
    {
        return;
    }

    midx = g_nstack_dmm_dfx_ops[0].type ? 0 : midx;
    g_nstack_dmm_dfx_ops[midx].update_dfx_data(fd, type, data);
}

void nstack_fd_dfx_update_dfx_data(int fd, int protoFd, int midx, int type,
                                   void *info)
{
    u16 data = 0;
    if (midx < 0 || fd < 0 || protoFd < 0)
        return;

    if (!dmm_fd_dfx_pool ||
        !g_nstack_dmm_dfx_ops ||
        !(g_nstack_dmm_dfx_ops[midx].update_dfx_data))
    {
        return;
    }

    switch (type)
    {
        case DMM_STAT_LONGEST_SEND_INTERVAL:
            if (dmm_fd_dfx_pool[fd].last_send_out_tick)
            {
                data =
                    nstack_dfx_calculate_elapse(dmm_fd_dfx_pool
                                                [fd].last_send_in_tick,
                                                dmm_fd_dfx_pool
                                                [fd].last_send_out_tick);
                nstack_dfx_state_update((u64) protoFd, midx,
                                        DMM_STAT_LONGEST_SEND_INTERVAL,
                                        &data);
            }
            break;
        case DMM_STAT_LONGEST_SEND_COST:
            data =
                nstack_dfx_calculate_elapse(dmm_fd_dfx_pool
                                            [fd].last_send_out_tick,
                                            dmm_fd_dfx_pool
                                            [fd].last_send_in_tick);
            nstack_dfx_state_update((u64) protoFd, midx,
                                    DMM_STAT_LONGEST_SEND_COST, &data);
            break;
        case DMM_STAT_LONGEST_RECV_INTERVAL:
            if (dmm_fd_dfx_pool[fd].last_recv_out_tick)
            {
                data =
                    nstack_dfx_calculate_elapse(dmm_fd_dfx_pool
                                                [fd].last_recv_in_tick,
                                                dmm_fd_dfx_pool
                                                [fd].last_recv_out_tick);
                nstack_dfx_state_update((u64) protoFd, midx,
                                        DMM_STAT_LONGEST_RECV_INTERVAL,
                                        &data);
            }
            break;
        case DMM_STAT_LONGEST_RECV_COST:
            data =
                nstack_dfx_calculate_elapse(dmm_fd_dfx_pool
                                            [fd].last_recv_out_tick,
                                            dmm_fd_dfx_pool
                                            [fd].last_recv_in_tick);
            nstack_dfx_state_update((u64) protoFd, midx,
                                    DMM_STAT_LONGEST_RECV_COST, &data);
            break;
        default:
            nstack_dfx_state_update((u64) protoFd, midx,
                                    DMM_STAT_LONGEST_RECV_COST, info);
            break;
    }
}

int nstack_dfx_init_ops(nstack_dmm_stack_ops_t * ops)
{
    int i;

    if (!ops)
        return -1;

    g_nstack_dmm_dfx_ops =
        malloc(sizeof(nstack_dmm_stack_ops_t) * NSTACK_MAX_MODULE_NUM);
    if (!g_nstack_dmm_dfx_ops)
    {
        NSSOC_LOGERR("alloc dfx ops failed");
        return -1;
    }
    if (EOK !=
        memset_s(g_nstack_dmm_dfx_ops,
                 sizeof(nstack_dmm_stack_ops_t) * NSTACK_MAX_MODULE_NUM, 0,
                 sizeof(nstack_dmm_stack_ops_t) * NSTACK_MAX_MODULE_NUM))
    {
        NSSOC_LOGERR("memory set failed");
        return -1;
    }
    switch (ops[0].type)
    {
        case 0:                //nsocket
            for (i = 0; i < NSTACK_MAX_MODULE_NUM; i++)
            {
                g_nstack_dmm_dfx_ops[i].update_dfx_data =
                    ops[i].update_dfx_data;
                g_nstack_dmm_dfx_ops[i].type = ops[i].type;
            }

            /*all stack just use the same time tick (default is used the first one) */
            for (i = 0; i < NSTACK_MAX_MODULE_NUM; i++)
            {
                if (ops[i].get_stack_tick)
                {
                    g_nstack_dmm_dfx_ops[0].get_stack_tick =
                        ops[i].get_stack_tick;
                    break;
                }
            }

            break;
        default:
            for (i = 0; i < NSTACK_MAX_MODULE_NUM; i++)
            {
                g_nstack_dmm_dfx_ops[i] = *ops;
            }
            break;
    }

    return 0;
}
