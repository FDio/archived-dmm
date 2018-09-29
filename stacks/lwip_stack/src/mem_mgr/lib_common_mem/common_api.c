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

#include <string.h>
#include "common_mem_api.h"
#include "common_mem_pal.h"
#include "nstack_log.h"
#include "nstack_securec.h"
#include "common_func.h"
#include "dmm_sys.h"

void
sys_sem_init_v2 (sys_sem_t_v2 sem)
{
  sem->locked = 1;
}

/** Returns the current time in milliseconds,
 * may be the same as sys_jiffies or at least based on it. */
u32_t
sys_now (void)
{
  struct timespec now;

  if (unlikely (0 != clock_gettime (CLOCK_MONOTONIC, &now)))
    {
      NSCOMM_LOGERR ("Failed to get time, errno = %d", errno);
    }

  return 1000 * now.tv_sec + now.tv_nsec / 1000000;
}

long
sys_jiffies (void)
{
  return sys_now ();
}

err_t
sys_sem_new_v2 (sys_sem_t_v2 * sem, u8_t isUnLockd)
{
  int retVal;
  if (!sem)
    {
      return -1;
    }
  *sem = malloc (sizeof (common_mem_spinlock_t));

  if (NULL == *sem)
    {
      return -1;
    }
  else
    {
      retVal =
        MEMSET_S (*sem, sizeof (common_mem_spinlock_t), 0,
                  sizeof (common_mem_spinlock_t));
      if (EOK != retVal)
        {
          NSCOMM_LOGERR ("MEMSET_S failed]ret=%d", retVal);
          free (*sem);
          *sem = NULL;
          return -1;
        }
      common_mem_spinlock_init (*sem);
    }

  if (!isUnLockd)
    {
      common_mem_spinlock_lock (*sem);
    }

  return 0;
}

void
sys_sem_free_v2 (sys_sem_t_v2 * sem)
{
  if ((sem != NULL) && (*sem != NULL))
    {
      free (*sem);
      *sem = NULL;
    }
  else
    {
    }
}

void
sys_sem_signal_v2 (sys_sem_t_v2 * sem)
{
  common_mem_spinlock_unlock (*sem);
}

void
sys_sem_signal_s_v2 (sys_sem_t_v2 sem)
{
  common_mem_spinlock_unlock (sem);
}

u32_t
sys_arch_sem_trywait_v2 (sys_sem_t_v2 * sem)
{
  return (u32_t) common_mem_spinlock_trylock (*sem);
}

u32_t
sys_arch_sem_wait_v2 (sys_sem_t_v2 * pstsem)
{
  common_mem_spinlock_lock (*pstsem);
  return 0;
}

u32_t
sys_arch_sem_wait_s_v2 (sys_sem_t_v2 sem)
{
  common_mem_spinlock_lock (sem);
  return 0;
}
