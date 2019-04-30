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

#pragma GCC diagnostic ignored "-Wcpp"
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <errno.h>
#include<sys/types.h>
#include<sys/time.h>
#include<unistd.h>
#include <string.h>
#include <pthread.h>
#include "types.h"
#include "nstack_sockops.h"
#include "nstack_log.h"
#include "linux_kernel_module.h"
#include "linux_kernel_socket.h"
#include "nsfw_base_linux_api.h"
#include "nstack_fd_mng.h"
#include "nstack_epoll_api.h"
#include "dmm_spinlock.h"
#include "nsfw_mem_api.h"
#include "nstack_info_parse.h"
#include "nstack_eventpoll.h"
#include "nstack_rd_api.h"

#define SK_MAX_EP_EVENT 1024

void *krd_table = NULL;
kernel_stack_info_t g_ksInfo = {.thread_inited = ks_false };

/*design ensures that g_ksInfo is not write accessed at the same time.
only read is done simultaneously with no chance of other thread writing it.
so no protection needed.*/

/*no need to free these points because the function is always running */
/*point is set to NULL because it's freeed */
void *ks_ep_thread(void *arg)
{
    int eventNum = 0;
    int loop = 0;
    int retval = 0;
    int ret;
    nsep_epollInfo_t *epInfo;
    struct epoll_event *events =
        (struct epoll_event *) malloc(SK_MAX_EP_EVENT *
                                      sizeof(struct epoll_event));
    struct epoll_event *innerEvt =
        (struct epoll_event *) malloc(SK_MAX_EP_EVENT *
                                      sizeof(struct epoll_event));
    struct list_node *fdEpiHead;
    struct list_node *node;
    struct epitem *epi = NULL;
    struct eventpoll *ep = NULL;

    if (NULL == events || NULL == innerEvt)
    {
        NSSOC_LOGERR("malloc events failed");

        if (events)
        {
            free(events);
            events = NULL;      /* Set NULL to pointer after free */
        }

        if (innerEvt)
        {
            free(innerEvt);
            innerEvt = NULL;    /* Set NULL to pointer after free */
        }

        /* When ks_ep_thread failed, it should set g_ksInfo.thread_inited ks_true, otherwise,it will result kernel_stack_register in dead loop */
        g_ksInfo.thread_inited = ks_true;
        return NULL;
    }

    retval =
        memset_s(events, SK_MAX_EP_EVENT * sizeof(struct epoll_event), 0,
                 SK_MAX_EP_EVENT * sizeof(struct epoll_event));
    retval |=
        memset_s(innerEvt, SK_MAX_EP_EVENT * sizeof(struct epoll_event), 0,
                 SK_MAX_EP_EVENT * sizeof(struct epoll_event));

    if (EOK != retval)
    {
        free(events);
        events = NULL;
        free(innerEvt);
        innerEvt = NULL;
        g_ksInfo.thread_inited = ks_true;
        return NULL;
    }

    NSTACK_CAL_FUN(&g_ksInfo.libcOps, epoll_create, (1), g_ksInfo.epfd);

    if (-1 == g_ksInfo.epfd)
    {
        g_ksInfo.thread_inited = ks_true;

        if (events)
        {
            free(events);
            events = NULL;      /* Set NULL to pointer after free */
        }

        if (innerEvt)
        {
            free(innerEvt);
            innerEvt = NULL;    /* Set NULL to pointer after free */
        }

        return NULL;
    }

    g_ksInfo.thread_inited = ks_true;

    do
    {

        NSTACK_CAL_FUN(&g_ksInfo.libcOps, epoll_wait,
                       (g_ksInfo.epfd, events, SK_MAX_EP_EVENT, -1),
                       eventNum);

        if (0 == eventNum)
        {
            sys_sleep_ns(0, 100000);

        }

        for (loop = 0; loop < eventNum; loop++)
        {

            NSSOC_LOGDBG("Epoll]events=%u,epfd=%d", events[loop].events,
                         events[loop].data.fd);

            if (events[loop].events & EPOLLIN)
            {
                int i = 0, num = 0, epfd = events[loop].data.fd;
                NSTACK_CAL_FUN(&g_ksInfo.libcOps, epoll_wait,
                               (epfd, innerEvt, SK_MAX_EP_EVENT, 0), num);

                if (0 == num)
                {
                    /* remove it becasue print in normal scenario */
                    NSSOC_LOGDBG("Num is zero]epfd=%d", epfd);
                    continue;
                }

                NSTACK_CAL_FUN(&g_ksInfo.libcOps, epoll_ctl,
                               (g_ksInfo.epfd, EPOLL_CTL_DEL, epfd, NULL),
                               ret);

                for (i = 0; i < num; i++)
                {
                    epInfo = nsep_get_info_by_sock(innerEvt[i].data.fd);

                    if (epInfo
                        && (epInfo->rmidx < 0
                            || epInfo->rmidx == g_ksInfo.regVal.type))
                    {
                        dmm_spin_lock_with_pid((dmm_spinlock_t
                                                *) (&epInfo->epiLock));
                        fdEpiHead =
                            (struct list_node *)
                            SHMEM_ADDR_SHTOL(epInfo->epiList.head);
                        node =
                            (struct list_node *)
                            SHMEM_ADDR_SHTOL(fdEpiHead->next);
                        while (node)
                        {

                            epi =
                                (struct epitem *) ep_list_entry(node,
                                                                struct
                                                                epitem,
                                                                fllink);

                            node =
                                (struct list_node *)
                                SHMEM_ADDR_SHTOL(node->next);
                            ep = (struct eventpoll *)
                                SHMEM_ADDR_SHTOL(epi->ep);

                            if (!(epi->event.events & innerEvt[i].events))
                            {
                                continue;
                            }

                            if (ep->pid != get_sys_pid())
                            {
                                continue;
                            }

                            epi->revents |= innerEvt[i].events;
                        }

                        dmm_spin_unlock((dmm_spinlock_t
                                         *) (&epInfo->epiLock));
                        g_ksInfo.regVal.event_cb(epInfo, innerEvt[i].events,
                                                 EVENT_INFORM_APP);
                        NSSOC_LOGDBG
                            ("Kernel got one event]i=%d,fd=%d,events=%u", i,
                             innerEvt[i].data.fd, innerEvt[i].events);
                    }

                }
            }
        }
    }
    while (1);
}

int kernel_load_default_rd(void *table)
{
    rd_ip_data ip_data;
    ip_data.addr = inet_addr("127.0.0.1");      // loopback address
    ip_data.masklen = 0;
    ip_data.resev[0] = ip_data.resev[1] = 0;
    (void) nstack_rd_ip_node_insert(RD_KERNEL_NAME, &ip_data, table);
    NSSOC_LOGINF("successfully load default rd");
    return 0;
}

void *kernel_get_ip_shmem()
{
    return krd_table;
}

int kernel_module_init()
{
    krd_table = nstack_local_rd_malloc();

    if (!krd_table)
    {
        NSSOC_LOGERR("kernel rd table create failed!");
        return -1;
    }

    if (nstack_rd_parse(RD_KERNEL_NAME, krd_table))
    {
        NSSOC_LOGWAR("kernel parse rd data failed, load default instead");
        nstack_rd_table_clear(krd_table);
        return kernel_load_default_rd(krd_table);
    }

    return 0;
}

int kernel_stack_register
    (nstack_socket_ops * ops,
     nstack_event_ops * val, nstack_proc_ops * fddeal)
{
    /* Input parameter validation */
    if ((NULL == ops) || (NULL == val) || (NULL == fddeal))
    {
        NSPOL_LOGERR("input param is NULL");
        return ks_fail;
    }

#undef NSTACK_MK_DECL
#define NSTACK_MK_DECL(ret, fn, args) \
    g_ksInfo.libcOps.pf##fn = nsfw_base_##fn;
/*this file can be included more than once */
#include "declare_syscalls.h.tmpl"

    g_ksInfo.epfd = -1;
    g_ksInfo.regVal = *val;

#ifdef KERNEL_FD_SUPPORT
    g_ksInfo.thread_inited = ks_false;

    NSSOC_LOGDBG("start to regist stack");

    if (pthread_create(&g_ksInfo.ep_thread, NULL, ks_ep_thread, NULL))
    {
        NSPOL_LOGERR("Err!");
        return ks_fail;
    }

    /* The earlier thread "ep_thread" created will exit automatically when
       return failure from below if any failure */
    int retval = 0;

    if (pthread_setname_np(g_ksInfo.ep_thread, K_EPOLL_THREAD_NAME))
    {
        NSMON_LOGERR("pthread_setname_np failed for ep_thread]retval=%d",
                     retval);
        /*set thread name failed no need to return */
    }

    NSSOC_LOGDBG("New thread started");

    do
    {
        sys_sleep_ns(0, 0);
    }
    while (!g_ksInfo.thread_inited);

    if (-1 == g_ksInfo.epfd)
    {
        NSPOL_LOGERR("Err!");
        retval = -1;
    }

#endif

    *ops = g_ksInfo.libcOps;

    NSTACK_SET_OPS_FUN(ops, listen, lk_listen);
    NSTACK_SET_OPS_FUN(ops, epoll_ctl, lk_epollctl);

    /* don't close file descriptor */

    fddeal->module_init = kernel_module_init;
    fddeal->get_ip_shmem = kernel_get_ip_shmem;

#ifdef KERNEL_FD_SUPPORT
    return retval ? ks_fail : ks_success;
#else
    return ks_success;
#endif
}
