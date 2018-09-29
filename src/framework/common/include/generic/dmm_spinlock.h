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
#ifndef _DMM_SPINLOCK_H_
#define _DMM_SPINLOCK_H_

#include "dmm_pause.h"

typedef struct
{
  volatile int lock;
} dmm_spinlock_t;

inline static void
dmm_spin_init (dmm_spinlock_t * spinlock)
{
  spinlock->lock = 0;
}

static inline int
dmm_spin_trylock_with (dmm_spinlock_t * spinlock, int value)
{
  return __sync_bool_compare_and_swap (&spinlock->lock, 0, value);
}

static inline void
dmm_spin_lock_with (dmm_spinlock_t * spinlock, int value)
{
  while (!dmm_spin_trylock_with (spinlock, value))
    {
      DMM_PAUSE_WHILE (spinlock->lock);
    }
}

inline static void
dmm_spin_lock (dmm_spinlock_t * spinlock)
{
  dmm_spin_lock_with (spinlock, 1);
}

inline static int
dmm_spin_trylock (dmm_spinlock_t * spinlock)
{
  return dmm_spin_trylock_with (spinlock, 1);
}

inline static void
dmm_spin_unlock (dmm_spinlock_t * spinlock)
{
  __sync_lock_release (&spinlock->lock);
}

#endif /* #ifndef _DMM_SPINLOCK_H_ */
