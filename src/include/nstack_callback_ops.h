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

#ifndef __NSOCKET_CALLBACK_OPS_H__
#define __NSOCKET_CALLBACK_OPS_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>

/*
 *Standard api interface definition.
 *these interface is provided by Protocol stack to nStack
 */
typedef struct __nstack_socket_ops
{
#undef NSTACK_MK_DECL
#define NSTACK_MK_DECL(ret, fn, args)  ret (*pf##fn) args
#include "declare_syscalls.h.tmpl"
} nstack_socket_ops;

typedef struct nstack_dmm_stack_ops_s
{
    void (*update_dfx_data) (uint64_t s, int type, void *data);
    void (*get_stack_tick) (void *data);
    int type;
} nstack_dmm_stack_ops_t;

/*
 *Interactive interface for Protocol stack and nStack defined here
 *these interface is provided by Protocol stack to nStack
 */
typedef struct __nstack_proc_ops
{
    int (*module_init) (void);
    int (*fork_init_child) (pid_t p, pid_t c);
    void (*fork_fd) (int s, pid_t p, pid_t c);
    void (*fork_free_fd) (int s);
    void (*(*ep_triggle)
          (int proFD, int triggle_ops, void *epinfo, void *epitem));
    int (*ep_getEvt) (int proFD);
    int (*route_match_byip) (void *addr);
    int (*peak) (int s);
    void (*set_app_info) (int proFD, void *appinfo);
    /* set param list to void if not need param */
    void (*app_touch) (void);   /* app send its version info to daemon-stack */
    void (*set_close_stat) (int s, int status);
    void (*update_dfx_data) (uint64_t s, int type, void *data);
    void (*get_stack_tick) (void *data);
    void *(*get_ip_shmem) (void);
    int (*module_init_pre) (void *, void *, int, int);
} nstack_proc_ops;

/*
 *The event notify interface provided to the protocol stack by nStack
 *these interface is provided by nStack to Protocol stack
 */
typedef struct __nstack_event_ops
{
    void *handle;               /*current so file handler */
    int type;                   /*nstack is assigned to the protocol stack and needs to be passed to nstack when the event is reported */
    void (*event_cb) (void *epif, int event, int postFlag);
} nstack_event_ops;

/*
 *Module registration interface.
 *ouput param:posix_ps,proc_ops
 *input param:event_ops
 */
typedef int (*nstack_stack_register_fn) (nstack_socket_ops * socketops,
                                         nstack_event_ops * event_ops,
                                         nstack_proc_ops * proc_ops);
int nstack_dfx_init_ops(nstack_dmm_stack_ops_t * ops);

int nstack_epoll_init(int flag, int ns_sync_mod);

#endif
