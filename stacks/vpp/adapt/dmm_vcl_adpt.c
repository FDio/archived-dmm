/*
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

#define _GNU_SOURCE
#include <pthread.h>
#include <dlfcn.h>
#include <sys/epoll.h>
#include "dmm_vcl.h"
#include "nstack_log.h"
#include "nstack_rd_api.h"

#define DMM_VCL_ADPT_DEBUG dmm_vcl_debug
static unsigned int dmm_vcl_debug;

dmm_vcl_t g_dmm_vcl;
dmm_vcl_event_t g_dmm_vcl_event[DMM_VCL_MAX_FD_VALUE] = { 0 };

void *vpprd_table = NULL;
void *vpp_get_ip_shmem()
{
    return vpprd_table;
}

void *vpphs_ep_ctl_ops(int proFD, int ctl_ops, void *pdata, void *event)
{
    struct epoll_event tmpEvt;
    int ret = 0;
    int dmm_epfd;
    g_dmm_vcl_event[proFD].pdata = pdata;
    g_dmm_vcl_event[proFD].proFD = proFD;

    tmpEvt.data.ptr = &g_dmm_vcl_event[proFD];
    tmpEvt.events = *(int *) event;
    tmpEvt.events |= (EPOLLIN | EPOLLOUT);

    if (DMM_VCL_ADPT_DEBUG > 0)
        NSSOC_LOGINF("DMM VCL ADPT<%d>: fd=%d,ops=%d, events=%u",
                     getpid(), proFD, ctl_ops, event);

    dmm_epfd = g_dmm_vcl.epfd;
    switch (ctl_ops)
    {
        case nstack_ep_triggle_add:
            ret =
                g_dmm_vcl.p_epoll_ctl(dmm_epfd, EPOLL_CTL_ADD, proFD,
                                      &tmpEvt);
            break;
        case nstack_ep_triggle_mod:
            ret =
                g_dmm_vcl.p_epoll_ctl(dmm_epfd, EPOLL_CTL_MOD, proFD,
                                      &tmpEvt);
            break;
        case nstack_ep_triggle_del:
            ret =
                g_dmm_vcl.p_epoll_ctl(dmm_epfd, EPOLL_CTL_DEL, proFD,
                                      &tmpEvt);
            break;
        default:
            ret = -1;
            break;
    }
    if (ret == -1)
        return NULL;
    return pdata;
}

#define DMM_VCL_MAX_EP_EVENT 1024

static void *dmm_vcl_epoll_thread(void *arg)
{
    int num, i;

    struct epoll_event events[DMM_VCL_MAX_EP_EVENT];
    dmm_vcl_event_t vcl_event = { 0 };
    while (1)
    {
        num =
            g_dmm_vcl.p_epoll_wait(g_dmm_vcl.epfd, events,
                                   DMM_VCL_MAX_EP_EVENT, 100);

        for (i = 0; i < num; ++i)
        {
            if (DMM_VCL_ADPT_DEBUG > 0)
                NSSOC_LOGINF
                    ("DMM_VCL_ADPT<%d>: dmm_vcl_epoll i[%d] events=%u, epfd=%d, ptr=%d",
                     getpid(), i, events[i].events, events[i].data.fd,
                     events[i].data.ptr);
            vcl_event = *(dmm_vcl_event_t *) (events[i].data.ptr);
            g_dmm_vcl_event[vcl_event.proFD].event_type = events[i].events;
            g_dmm_vcl.regVal.event_cb(vcl_event.pdata, events[i].events,
                                      EVENT_INFORM_APP);
        }
    }

    return NULL;
}

int dmm_vpphs_init()
{
    char *env_var_str;
    int rv = 0;

    env_var_str = getenv(DMM_VCL_ENV_DEBUG);
    if (env_var_str)
    {
        u32 tmp;
        if (sscanf(env_var_str, "%u", &tmp) != 1)
        {
            NSSOC_LOGINF
                ("DMM_VCL_ADPT<%d>: WARNING: Invalid debug level specified "
                 "in the environment variable " DMM_VCL_ENV_DEBUG " (%s)!\n",
                 getpid(), env_var_str);
        }
        else
        {
            dmm_vcl_debug = tmp;
            if (DMM_VCL_ADPT_DEBUG > 0)
                NSSOC_LOGINF
                    ("DMM_VCL_ADPT<%d>: configured DMM VCL ADPT debug (%u) from "
                     "DMM_VCL_ENV_DEBUG ", getpid(), dmm_vcl_debug);
        }
    }

    vpprd_table = nstack_local_rd_malloc();
    if (!vpprd_table)
    {
        NSSOC_LOGERR("vpp_hoststack rd table create failed!");
        return -1;
    }
    if (nstack_rd_parse("vpp_hoststack", vpprd_table))
    {
        NSSOC_LOGWAR("no rd data got!");
        NSSOC_LOGWAR("rsocket parse rd data failed");
        nstack_rd_table_clear(vpprd_table);
        return -1;
    }
    g_dmm_vcl.epfd = g_dmm_vcl.p_epoll_create(1000);
    if (g_dmm_vcl.epfd < 0)
        return g_dmm_vcl.epfd;

    rv = pthread_create(&g_dmm_vcl.epoll_threadid, NULL, dmm_vcl_epoll_thread,
                        NULL);
    if (rv != 0)
    {
        NSSOC_LOGINF("dmm vcl epoll thread create fail, errno:%d!", errno);
        g_dmm_vcl.p_close(g_dmm_vcl.epfd);
        g_dmm_vcl.epfd = -1;
        return rv;
    }

    rv = pthread_setname_np(g_dmm_vcl.epoll_threadid, "dmm_vcl_epoll");
    if (rv != 0)
    {
        NSSOC_LOGINF
            ("pthread_setname_np failed for dmm_vcl_epoll, rv=%d, errno:%d",
             rv, errno);
    }

    return rv;
}

int vpp_getEvt(int fd)
{
    return g_dmm_vcl_event[fd].event_type;
}

int
vpp_hoststack_stack_register(nstack_socket_ops * ops, nstack_event_ops * val,
                             nstack_proc_ops * fddeal)
{

#undef NSTACK_MK_DECL
#define NSTACK_MK_DECL(ret, fn, args) \
    ops->pf ## fn = (typeof(((nstack_socket_ops*)0)->pf ## fn))dlsym(val->handle,  # fn);
#include "declare_syscalls.h.tmpl"
    ops->pfepoll_create = NULL;

    g_dmm_vcl.p_epoll_ctl = dlsym(val->handle, "epoll_ctl");
    g_dmm_vcl.p_epoll_create = dlsym(val->handle, "epoll_create1");
    g_dmm_vcl.p_epoll_wait = dlsym(val->handle, "epoll_wait");
    g_dmm_vcl.p_close = dlsym(val->handle, "close");
    g_dmm_vcl.regVal = *val;

    fddeal->module_init = dmm_vpphs_init;
    fddeal->fork_init_child = dmm_vpphs_init;
    fddeal->fork_free_fd = NULL;
    fddeal->ep_triggle = vpphs_ep_ctl_ops;
    fddeal->get_ip_shmem = vpp_get_ip_shmem;
    fddeal->peak = NULL;
    fddeal->ep_getEvt = vpp_getEvt;

    return 0;
}
