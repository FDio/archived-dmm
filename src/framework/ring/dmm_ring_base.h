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
#ifndef _DMM_RING_BASE_H_
#define _DMM_RING_BASE_H_

#ifndef _DMM_RING_H_
#error include dmm_ring.h please
#endif

inline static int
__move_head (volatile int *head, int ring_size,
             int old_head, int real_num, int is_single)
{
  int new_head = old_head + real_num;

  if (new_head >= ring_size)
    {
      new_head -= ring_size;
    }

  if (is_single)
    {
      *head = new_head;
      return 1;
    }

  return dmm_atomic_swap ((dmm_atomic_t *) head, old_head, new_head);
}

inline static int
dmm_enqueue_prep (struct dmm_ring *ring, const int num,
                  int *pos, const int fixed, int is_sp)
{
  int succ, real, head;
  const int ring_size = ring->size;

  do
    {
      head = ring->prod_head;

      dmm_barrier ();

      if ((real = ring->cons_tail - head - 1) < 0)
        real += ring_size;

      if (real >= num)
        real = num;
      else if (fixed)
        return 0;

      if (real <= 0)
        return 0;

      succ = __move_head (&ring->prod_head, ring_size, head, real, is_sp);
    }
  while (!succ);

  *pos = head;
  return real;
}

inline static int
dmm_enqueue_copy (struct dmm_ring *ring, int pos, void **from, int num)
{
  const int ring_size = ring->size;
  void **box = (void **) (ring + 1);

  while (num > 0)
    {
      box[pos++] = *from++;
      if (pos >= ring_size)
        pos = 0;
      --num;
    }

  return pos;
}

inline static void
dmm_enqueue_done (struct dmm_ring *ring, int pos, int new_pos, int is_sp)
{
  dmm_barrier ();

  if (!is_sp)
    {
      while (ring->prod_tail != pos)
        dmm_pause ();
    }

  ring->prod_tail = new_pos;
}

inline static int
dmm_enqueue_copy_array (struct dmm_ring *ring, int pos,
                        void *array, int num, size_t elt_size)
{
  const int ring_size = ring->size;
  void **box = (void **) (ring + 1);
  char *from = (char *) array;

  while (num > 0)
    {
      box[pos++] = from;
      if (pos >= ring_size)
        pos = 0;
      from += elt_size;
      --num;
    }

  return pos;
}

inline static int
dmm_dequeue_prep (struct dmm_ring *ring, const int num, int *pos,
                  const int fixed, int is_sc)
{
  int succ, real, head;
  const int ring_size = ring->size;

  do
    {
      head = ring->cons_head;

      dmm_barrier ();

      if ((real = ring->prod_tail - head) < 0)
        real += ring_size;

      if (real >= num)
        real = num;
      else if (fixed)
        return 0;

      if (real <= 0)
        return 0;

      succ = __move_head (&ring->cons_head, ring_size, head, real, is_sc);
    }
  while (!succ);

  *pos = head;
  return real;
}

inline static int
dmm_dequeue_copy (struct dmm_ring *ring, int pos, void **to, int num)
{
  const int ring_size = ring->size;
  void **box = (void **) (ring + 1);

  while (num > 0)
    {
      *to++ = box[pos++];
      if (pos >= ring_size)
        pos = 0;
      --num;
    }

  return pos;
}

inline static void
dmm_dequeue_done (struct dmm_ring *ring, int pos, int new_pos, int is_sc)
{
  dmm_barrier ();

  if (!is_sc)
    {
      while (ring->cons_tail != pos)
        dmm_pause ();
    }

  ring->cons_tail = new_pos;
}

#endif
