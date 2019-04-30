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

#ifndef __NSTACK_DMM_DFX_API_H__
#define __NSTACK_DMM_DFX_API_H__
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include<netinet/in.h>
#include <sys/epoll.h>
#include "types.h"

struct stat_epfd_info
{
    u64 epoll_wait_tick;
    i32 epfd;
    pid_t hhpid;
    u8 epoll_fork_flag;
    u8 reserve_8[3];
    u32 ep_sleepTime;
};

typedef struct stat_epitem_info
{
    struct epoll_event event;
    int is_linked;
} stat_epitem_info_t;

typedef struct __ns_udp_route_info
{
    struct sockaddr_in iaddr;
    int selectmod;
} ns_udp_route_Inf;

typedef enum nstack_dmm_type_e
{
    DMM_STAT_LONGEST_SEND_INTERVAL = 0,
    DMM_STAT_LONGEST_SEND_COST,
    DMM_STAT_LONGEST_RECV_INTERVAL,
    DMM_STAT_LONGEST_RECV_COST,
    DMM_STAT_ROUTE_INFO,
    DMM_APP_EPOLL_WAIT_EVENT,
    DMM_APP_EPOLL_WAIT_FAIL,
    DMM_APP_EPOLL_WAIT_GET_TICK,
    DMM_APP_EPOLL_ADD_TICK,
    DMM_APP_EPOLL_MOD_TICK,
    DMM_APP_EPOLL_WAIT_CALL_TICK,
    DMM_APP_EPOLL_DEL_TICK,
    DMM_APP_SELECT_FAIL,
    DMM_MAIN_REPORT_EVENT_TICK,
    DMM_MAIN_REPORT_EP_CNT,

    DMM_DFX_MAX = 64
} nstack_dmm_type_t;

void nstack_dfx_state_update(u64 fd, int midx, nstack_dmm_type_t type,
                             void *data);
void nstack_fd_dfx_update_dfx_data(int fd, int protoFd, int midx, int type,
                                   void *info);
#endif
