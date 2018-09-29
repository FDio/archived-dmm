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

#define DMM_RING_MAX_NUM 0x7FFFFFFE     /* 2,147,483,646 */

#define DMM_RING_INIT_SP 0x0001
#define DMM_RING_INIT_SC 0x0002
#define DMM_RING_INIT_MPMC 0
#define DMM_RING_INIT_SPSC (DMM_RING_INIT_SP | DMM_RING_INIT_SC)

struct dmm_ring
{
  int size;
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

#include "dmm_ring_base.h"

void dmm_ring_dump (struct dmm_ring *ring, int list);
int dmm_ring_init (struct dmm_ring *ring, int num, int flag);
int dmm_pool_init (struct dmm_ring *pool, size_t elt_size,
                   int num, uint32_t flag);

inline static size_t
dmm_ring_bufsize (int num)
{
  size_t size = sizeof (struct dmm_ring);

  size += (sizeof (void *) * (num + 1));

  return dmm_align (size, DMM_CACHE_LINE_SIZE);
}

inline static size_t
dmm_pool_arraysize (int num, int elt_size)
{
  const size_t size = elt_size * num;
  return dmm_align (size, DMM_CACHE_LINE_SIZE);
}

inline static size_t
dmm_pool_bufsize (int num, int elt_size)
{
  return dmm_ring_bufsize (num) + dmm_pool_arraysize (num, elt_size);
}

inline static int
dmm_ring_count (struct dmm_ring *ring)
{
  const int count = ring->prod_tail - ring->cons_head;

  if (count >= 0)
    return count;
  return count + ring->size;
}

inline static int
dmm_ring_free_count (struct dmm_ring *ring)
{
  const int count = ring->cons_tail - ring->prod_head;

  if (count >= 0)
    return count;
  return count + ring->size;
}

/* enqueue several objects in a ring.
       ring: point to the ring
          p: object pointer list array
        num: number of object
      fixed: enqueue fixed number
single_cons: is single producer
   <return>: number of enqueued object, 0: queue is full
*/
inline static int
dmm_ring_enqueue (struct dmm_ring *ring, void **p, int num,
                  int fixed, int is_sp)
{
  int n, pos, new_pos;

  n = dmm_enqueue_prep (ring, num, &pos, fixed, is_sp);

  if (n == 0)
    return 0;

  new_pos = dmm_enqueue_copy (ring, pos, p, n);

  dmm_enqueue_done (ring, pos, new_pos, is_sp);

  return n;
}

inline static int
dmm_fix_enqueue (struct dmm_ring *ring, void **p, int num)
{
  return dmm_ring_enqueue (ring, p, num, 1, ring->is_sp);
}

inline static int
dmm_var_enqueue (struct dmm_ring *ring, void **p, int num)
{
  return dmm_ring_enqueue (ring, p, num, 0, ring->is_sp);
}

inline static int
dmm_enqueue (struct dmm_ring *ring, void *p)
{
  return dmm_var_enqueue (ring, &p, 1);
}

inline static int
dmm_array_enqueue (struct dmm_ring *ring, void *array,
                   int num, size_t elt_size)
{
  int n, pos, new_pos;

  n = dmm_enqueue_prep (ring, num, &pos, 0, ring->is_sp);

  if (n == 0)
    return 0;

  new_pos = dmm_enqueue_copy_array (ring, pos, array, n, elt_size);

  dmm_enqueue_done (ring, pos, new_pos, ring->is_sp);

  return n;
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
dmm_ring_dequeue (struct dmm_ring *ring, void **p, int num,
                  int fixed, int single_cons)
{
  int n, pos, new_pos;

  n = dmm_dequeue_prep (ring, num, &pos, fixed, single_cons);

  if (n == 0)
    return 0;

  new_pos = dmm_dequeue_copy (ring, pos, p, n);

  dmm_dequeue_done (ring, pos, new_pos, single_cons);

  return n;
}

inline static int
dmm_fix_dequeue (struct dmm_ring *ring, void **p, int num)
{
  return dmm_ring_dequeue (ring, p, num, 1, ring->is_sc);
}

inline static int
dmm_var_dequeue (struct dmm_ring *ring, void **p, int num)
{
  return dmm_ring_dequeue (ring, p, num, 0, ring->is_sc);
}

inline static int
dmm_dequeue (struct dmm_ring *ring, void **p)
{
  return dmm_var_dequeue (ring, p, 1);
}

#endif
