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

#ifndef __NSTACK_SYNC_H__
#define __NSTACK_SYNC_H__

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
#endif

#include <sys/ipc.h>
#include <sys/sem.h>
#include <semaphore.h>
#include "types.h"
#include "nsfw_mgr_com_api.h"

#define NS_SEM_ARGS_SIZE     8

typedef enum ns_sync_type_e
{
    NS_SYNC_SEM_TRY,
    NS_SYNC_SYSV_MSG,
    NS_SYNC_UNIX,               /*need to do */
    NS_SYNC_MAX
} ns_sync_type_t;

typedef struct ns_sysv_type_s
{
    key_t key;
    i32 sock_id;
    i32 stack_id;
} ns_sysv_t;

typedef struct ns_sem_type_s
{
    sem_t semphore;
    ns_sysv_t sysv;
    char args[NS_SEM_ARGS_SIZE];

} ns_sem_type_t;

typedef struct ns_sync_sem_fun_s
{
    i32(*ns_sync_sem_init) (ns_sem_type_t * sem, i32 pshared, u32 value);
    i32(*ns_sync_sem_timedwait) (ns_sem_type_t * sem, i32 timeout, u32 sleeptime);      /* milliseconds */
    i32(*ns_sync_sem_post) (ns_sem_type_t * sem);
    i32(*ns_sync_sem_destroy) (ns_sem_type_t * sem);
} ns_sync_sem_fun_t;

extern ns_sync_sem_fun_t g_ns_sync_ops;
extern i32 ns_sync_sem_module_init(int type, ns_sync_type_t mode);

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif
