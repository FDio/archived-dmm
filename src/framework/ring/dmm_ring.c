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

#include <stdio.h>
#include <string.h>

#include "nstack_log.h"

#include "dmm_ring.h"
#include "dmm_ring_base.h"
#include "nsfw_mem_api.h"
#include "nstack_securec.h"
/* enqueue several objects in a ring.
       ring: point to the ring
          p: object pointer list array
        num: number of object
      fixed: enqueue fixed number
single_cons: is single producer
   <return>: number of enqueued object, 0: queue is full
*/
inline static int
dmm_ring_enqueue(struct dmm_ring *ring, void **p, int num,
                 int fixed, int is_sp)
{
    int n, pos, new_pos;

    n = dmm_enqueue_prep(ring, num, &pos, fixed, is_sp);

    if (n == 0)
        return 0;

    new_pos = dmm_enqueue_copy(ring, pos, p, n);

    dmm_enqueue_done(ring, pos, new_pos, is_sp);

    return n;
}

inline static int dmm_fix_enqueue(struct dmm_ring *ring, void **p, int num)
{
    return dmm_ring_enqueue(ring, p, num, 1, ring->is_sp);
}

inline static int dmm_var_enqueue(struct dmm_ring *ring, void **p, int num)
{
    return dmm_ring_enqueue(ring, p, num, 0, ring->is_sp);
}

inline static int dmm_enqueue(struct dmm_ring *ring, void *p)
{
    return dmm_var_enqueue(ring, &p, 1);
}

inline static int
dmm_array_enqueue(struct dmm_ring *ring, void *array,
                  int num, size_t elt_size)
{
    int n, pos, new_pos;

    n = dmm_enqueue_prep(ring, num, &pos, 0, ring->is_sp);

    if (n == 0)
        return 0;

    new_pos = dmm_enqueue_copy_array(ring, pos, array, n, elt_size);

    dmm_enqueue_done(ring, pos, new_pos, ring->is_sp);

    return n;
}

void dmm_ring_dump(struct dmm_ring *ring, int list)
{
    if (!ring)
        return;

    NSFW_LOGINF("ring:%p  size:%d flag:0x%x prod:%d-%d/%d cons:%d-%d/%d",
                ring, ring->size, ring->flag,
                ring->prod_head, ring->prod_tail, ring->is_sp,
                ring->cons_head, ring->cons_tail, ring->is_sc);
    if (list && dmm_ring_count(ring))
    {
        int count = 0;
        void **p = (void **) (ring + 1);
        int i = ring->cons_head;
        while (i != ring->prod_tail)
        {
            if ((count++ & 3) == 0)
                NSFW_LOGINF("\n");
            NSFW_LOGINF(" %d:%p", i, p[i]);
            if (++i >= ring->size)
                i = 0;
        }
    }
    NSFW_LOGINF("\n----------------\n");
}

int
dmm_ring_init(struct dmm_ring *ring, int num, size_t eltsize, int flag,
              unsigned char mem_type)
{
    if (num > DMM_RING_MAX_NUM)
        return -1;

    (void) memset_s(ring, sizeof(struct dmm_ring), 0,
                    sizeof(struct dmm_ring));

    ring->memtype = mem_type;
    ring->ringflag = NSFW_MRING_MPMC;

    ring->size = num + 1;
    ring->eltsize = eltsize;

    ring->prod_head = 0;
    ring->prod_tail = 0;
    ring->is_sp = flag & DMM_RING_INIT_SP;

    ring->cons_head = 0;
    ring->cons_tail = 0;
    ring->is_sc = flag & DMM_RING_INIT_SC;

    return 0;
}

/* dequeue several objects from a ring.
       ring: point to the ring
          p: save object array
        num: number of p
      fixed: dequeue fixed number
single_cons: is single consumer
   <return>: number of dequeued object, 0: queue is empty
*/
inline static int
dmm_ring_dequeue(struct dmm_ring *ring, void **p, int num,
                 int fixed, int single_cons)
{
    int n, pos, new_pos;

    n = dmm_dequeue_prep(ring, num, &pos, fixed, single_cons);

    if (n == 0)
        return 0;

    new_pos = dmm_dequeue_copy(ring, pos, p, n);

    dmm_dequeue_done(ring, pos, new_pos, single_cons);

    return n;
}

inline static int dmm_fix_dequeue(struct dmm_ring *ring, void **p, int num)
{
    return dmm_ring_dequeue(ring, p, num, 1, ring->is_sc);
}

inline static int dmm_var_dequeue(struct dmm_ring *ring, void **p, int num)
{
    return dmm_ring_dequeue(ring, p, num, 0, ring->is_sc);
}

inline static int dmm_dequeue(struct dmm_ring *ring, void **p)
{
    return dmm_var_dequeue(ring, p, 1);
}

int
dmm_pool_init(struct dmm_ring *pool, size_t elt_size, int num, int flag,
              unsigned char memtype)
{
    int ret;
    void *array;
    const size_t ring_size = dmm_ring_bufsize(num);

    if (0 != dmm_ring_init(pool, num, elt_size, flag, memtype))
    {
        NSFW_LOGERR
            ("init pool's ring failed, num:%d flag:0x%x ring_size:%lu", num,
             flag, ring_size);
        return -1;
    }

    array = (char *) pool + ring_size;
    ret = dmm_array_enqueue(pool, array, num, elt_size);
    if (ret != num)
    {
        NSFW_LOGERR("enqueue failed, num:%d elt_size:%lu", num, elt_size);
        return -1;
    }

    return 0;
}

int dmm_mem_enqueue(void *ring, void *p)
{
    return dmm_enqueue((struct dmm_ring *) ring, p);
}

int dmm_mem_dequeue(void *ring, void **p)
{
    return dmm_dequeue((struct dmm_ring *) ring, p);
}
