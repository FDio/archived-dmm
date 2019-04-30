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

#ifndef __NSTACK_EPOLL_API_H__
#define __NSTACK_EPOLL_API_H__
#include "types.h"

int nstack_epoll_init(int flag, int ns_sync_mod);

enum event_inform_state
{
    EVENT_NO_INFORM_APP,        /*just push the event, must following EVENT_MUST_INFORM_APP to wake up epoll */
    EVENT_INFORM_APP,           /*push event and wake up epoll */
    EVENT_MUST_INFORM_APP       /*merge all events not pulled by app */
};

typedef enum
{
    nstack_ep_triggle_add,
    nstack_ep_triggle_mod,
    nstack_ep_triggle_del,
    nstack_ep_triggle_inform_app,
    nstack_ep_event_max
} nstack_ep_triggle_ops_t;
void nsep_recycle_epfd(void *epinfo, u32 pid);
extern void nstack_epoll_event_enqueue(void *epif, int event, int postFlag);

extern int nstack_epoll_event_dequeue(void *epi_addr, int events);

#define NSTACK_EPOLL_EVENT_ADD(epInfo, event, flag)  do\
{\
    nstack_epoll_event_enqueue(epInfo, event, flag);\
}while(0)

#define NSTACK_EPOLL_EVENT_DEL(epitem, events) do\
{\
    nstack_epoll_event_dequeue(epitem, events);\
}while(0)

#endif
