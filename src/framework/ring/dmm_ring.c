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

void
dmm_ring_dump (struct dmm_ring *ring, int list)
{
  if (!ring)
    return;

  (void) printf ("ring:%p  size:%d flag:0x%x prod:%d-%d/%d cons:%d-%d/%d",
                 ring, ring->size, ring->flag,
                 ring->prod_head, ring->prod_tail, ring->is_sp,
                 ring->cons_head, ring->cons_tail, ring->is_sc);
  if (list && dmm_ring_count (ring))
    {
      int count = 0;
      void **p = (void **) (ring + 1);
      int i = ring->cons_head;
      while (i != ring->prod_tail)
        {
          if ((count++ & 3) == 0)
            (void) printf ("\n");
          (void) printf (" %d:%p", i, p[i]);
          if (++i >= ring->size)
            i = 0;
        }
    }
  (void) printf ("\n----------------\n");
}

int
dmm_ring_init (struct dmm_ring *ring, int num, int flag)
{
  if (num > DMM_RING_MAX_NUM)
    return -1;

  (void) memset (ring, 0, sizeof (struct dmm_ring));

  ring->size = num + 1;

  ring->prod_head = 0;
  ring->prod_tail = 0;
  ring->is_sp = flag & DMM_RING_INIT_SP;

  ring->cons_head = 0;
  ring->cons_tail = 0;
  ring->is_sc = flag & DMM_RING_INIT_SC;

  return 0;
}

int
dmm_pool_init (struct dmm_ring *pool, size_t elt_size, int num, uint32_t flag)
{
  int ret;
  void *array;
  const size_t ring_size = dmm_ring_bufsize (num);

  if (0 != dmm_ring_init (pool, num, flag))
    {
      NSFW_LOGERR ("init pool's ring failed, num:%d flag:0x%x ring_size:%lu",
                   num, flag, ring_size);
      return -1;
    }

  array = (char *) pool + ring_size;
  ret = dmm_array_enqueue (pool, array, num, elt_size);
  if (ret != num)
    {
      NSFW_LOGERR ("enqueue failed, num:%d elt_size:%lu", num, elt_size);
      return -1;
    }

  return 0;
}
