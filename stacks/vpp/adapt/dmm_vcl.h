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

#ifndef included_dmm_vcl_h
#define included_dmm_vcl_h

#include "nstack_epoll_api.h"
#include "nstack_callback_ops.h"

#define DMM_VCL_ENV_DEBUG     "DMM_VCL_DEBUG"
#define DMM_VCL_MAX_FD_VALUE 1024

typedef struct dmm_vcl
{
    int epfd;
    long unsigned int epoll_threadid;
    nstack_event_ops regVal;
    int (*p_epoll_create) (int size);
    unsigned int (*p_epoll_ctl) (int epFD, int proFD, int ctl_ops,
                                 struct epoll_event * events);
    unsigned int (*p_epoll_wait) (int epfd, struct epoll_event * events,
                                  int maxevents, int timeout);
    int (*p_close) (int fd);
} dmm_vcl_t;

typedef struct dmm_vcl_event
{
    void *pdata;
    int proFD;
    int event_type;
} dmm_vcl_event_t;

#endif /* included_dmm_vcl_h */
