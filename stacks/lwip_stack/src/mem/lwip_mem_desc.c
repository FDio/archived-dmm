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

#include <sys/types.h>
#include <unistd.h>
#include "nsfw_mem_api.h"
#include "nsfw_shmem_ring.h"
#include "nsfw_nshmem_ring.h"

/* *INDENT-OFF* */
nsfw_ring_ops g_ring_ops_arry_lwip[NSFW_MEM_TYPEMAX][NSFW_MPOOL_TYPEMAX] = {
    {
        {
            (nsfw_mem_ring_enqueue_fun)nsfw_shmem_ring_sp_enqueue, \
            (nsfw_mem_ring_dequeue_fun)nsfw_shmem_ring_sc_dequeue, \
            (nsfw_mem_ring_dequeuev_fun)nsfw_shmem_ring_sc_dequeuev
        },
        {
            (nsfw_mem_ring_enqueue_fun)nsfw_shmem_ring_mp_enqueue, \
            (nsfw_mem_ring_dequeue_fun)nsfw_shmem_ring_sc_dequeue, \
            (nsfw_mem_ring_dequeuev_fun)nsfw_shmem_ring_sc_dequeuev
        },
        {
            (nsfw_mem_ring_enqueue_fun)nsfw_shmem_ring_sp_enqueue, \
            (nsfw_mem_ring_dequeue_fun)nsfw_shmem_ring_mc_dequeue, \
            (nsfw_mem_ring_dequeuev_fun)nsfw_shmem_ring_mc_dequeuev
        },
        {
            (nsfw_mem_ring_enqueue_fun)nsfw_shmem_ring_mp_enqueue, \
            (nsfw_mem_ring_dequeue_fun)nsfw_shmem_ring_mc_dequeue, \
            (nsfw_mem_ring_dequeuev_fun)nsfw_shmem_ring_mc_dequeuev
        },
        {
            (nsfw_mem_ring_enqueue_fun)nsfw_shmem_ring_singlethread_enqueue, \
            (nsfw_mem_ring_dequeue_fun)nsfw_shmem_ring_singlethread_dequeue, \
            (nsfw_mem_ring_dequeuev_fun)nsfw_shmem_ring_singlethread_dequeuev
        }
    },
    {
        {
            (nsfw_mem_ring_enqueue_fun)nsfw_nshmem_ring_sp_enqueue, \
            (nsfw_mem_ring_dequeue_fun)nsfw_nshmem_ring_sc_dequeue, \
            (nsfw_mem_ring_dequeuev_fun)nsfw_nshmem_ring_sc_dequeuev
        },
        {
            (nsfw_mem_ring_enqueue_fun)nsfw_nshmem_ring_mp_enqueue, \
            (nsfw_mem_ring_dequeue_fun)nsfw_nshmem_ring_sc_dequeue, \
            (nsfw_mem_ring_dequeuev_fun)nsfw_nshmem_ring_sc_dequeuev
        },
        {
            (nsfw_mem_ring_enqueue_fun)nsfw_nshmem_ring_sp_enqueue, \
            (nsfw_mem_ring_dequeue_fun)nsfw_nshmem_ring_mc_dequeue, \
            (nsfw_mem_ring_dequeuev_fun)nsfw_nshmem_ring_mc_dequeuev
        },
        {
            (nsfw_mem_ring_enqueue_fun)nsfw_nshmem_ring_mp_enqueue, \
            (nsfw_mem_ring_dequeue_fun)nsfw_nshmem_ring_mc_dequeue, \
            (nsfw_mem_ring_dequeuev_fun)nsfw_nshmem_ring_mc_dequeuev
        },
        {
            (nsfw_mem_ring_enqueue_fun)nsfw_nshmem_ring_singlethread_enqueue, \
            (nsfw_mem_ring_dequeue_fun)nsfw_nshmem_ring_singlethread_dequeue, \
            (nsfw_mem_ring_dequeuev_fun)nsfw_nshmem_ring_singlethread_dequeuev
        }
    }
};
/* *INDENT-ON* */
