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

#ifndef _DMM_RING_H_
#define _DMM_RING_H_

#include <stdint.h>

#include "dmm_atomic.h"
#include "dmm_pause.h"
#include "dmm_barrier.h"
#include "dmm_common.h"
#include "types.h"

#define DMM_RING_MAX_NUM 0x7FFFFFFE     /* 2,147,483,646 */

#define DMM_RING_INIT_SP 0x0001
#define DMM_RING_INIT_SC 0x0002
#define DMM_RING_INIT_MPMC 0
#define DMM_RING_INIT_SPSC (DMM_RING_INIT_SP | DMM_RING_INIT_SC)

struct dmm_ring
{
    u8 memtype;                 //share, no share
    u8 ringflag;                //scmp, scsp, mcsp,mcmp
    int size;                   //size of ring
    size_t eltsize;             //for sppool, it is the size of per buf, if is ring, eltsize is zero.
    uint32_t flag;

    volatile int prod_head;
    volatile int prod_tail;
    int is_sp;
    int _prod_pad;

    volatile int cons_head;
    volatile int cons_tail;
    int is_sc;
    int _cons_pad;
} _dmm_cache_aligned;

void dmm_ring_dump(struct dmm_ring *ring, int list);
int dmm_ring_init(struct dmm_ring *ring, int num, size_t eltsize, int flag,
                  unsigned char memtype);
int dmm_pool_init(struct dmm_ring *pool, size_t elt_size, int num, int flag,
                  unsigned char memtype);
int dmm_mem_enqueue(void *ring, void *p);
int dmm_mem_dequeue(void *ring, void **p);

inline static size_t dmm_ring_bufsize(int num)
{
    size_t size = sizeof(struct dmm_ring);

    size += (sizeof(void *) * (num + 1));

    return dmm_align(size, DMM_CACHE_LINE_SIZE);
}

inline static size_t dmm_pool_arraysize(int num, size_t elt_size)
{
    const size_t size = elt_size * num;
    return dmm_align(size, DMM_CACHE_LINE_SIZE);
}

inline static size_t dmm_pool_bufsize(int num, size_t elt_size)
{
    return dmm_ring_bufsize(num) + dmm_pool_arraysize(num, elt_size);
}

inline static int dmm_ring_count(struct dmm_ring *ring)
{
    const int count = ring->prod_tail - ring->cons_head;

    if (count >= 0)
        return count;
    return count + ring->size;
}

inline static int dmm_ring_free_count(struct dmm_ring *ring)
{
    const int count = ring->cons_tail - ring->prod_head;

    if (count >= 0)
        return count;
    return count + ring->size;
}

#endif
