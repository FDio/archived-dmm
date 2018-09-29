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

#include "nstack_share_res.h"
#include "types.h"
#include "nsfw_recycle_api.h"
#include "nstack_securec.h"
#include "nstack_log.h"
#include "nsfw_maintain_api.h"
#include "nstack_types.h"

#include "dmm_memory.h"

#define NSTACK_SHARE_FORK_LOCK "share_fork_lock"

typedef struct
{
  dmm_spinlock_t *fork_share_lock;
} nstack_share_res;

NSTACK_STATIC nstack_share_res g_nstack_share_res;

NSTACK_STATIC int
nstack_create_share_fork_lock ()
{
  g_nstack_share_res.fork_share_lock = (dmm_spinlock_t *)
    dmm_locked_map (sizeof (dmm_spinlock_t), NSTACK_SHARE_FORK_LOCK);
  if (!g_nstack_share_res.fork_share_lock)
    {
      NSSOC_LOGERR ("nsfw_mem_zone_create failed]name=%s",
                    NSTACK_SHARE_FORK_LOCK);
      return -1;
    }

  dmm_spin_init (g_nstack_share_res.fork_share_lock);

  NSSOC_LOGDBG ("ok");
  return 0;
}

NSTACK_STATIC int
nstack_lookup_share_fork_lock ()
{
  g_nstack_share_res.fork_share_lock = (dmm_spinlock_t *)
    dmm_lookup (NSTACK_SHARE_FORK_LOCK);
  if (!g_nstack_share_res.fork_share_lock)
    {
      NSSOC_LOGERR ("nsfw_mem_zone_lookup failed]name=%s",
                    NSTACK_SHARE_FORK_LOCK);
      return -1;
    }

  NSSOC_LOGDBG ("ok");

  return 0;
}

int
nstack_init_share_res ()
{
  if (nstack_create_share_fork_lock () != 0)
    {
      return -1;
    }

  return 0;
}

int
nstack_attach_share_res ()
{
  if (nstack_lookup_share_fork_lock () != 0)
    {
      return -1;
    }
#if 0
  if (nstack_lookup_share_global_tick () != 0)
    {
      return -1;
    }
#endif
  return 0;
}

dmm_spinlock_t *
nstack_get_fork_share_lock ()
{
  return g_nstack_share_res.fork_share_lock;
}

NSTACK_STATIC nsfw_rcc_stat
nstack_recycle_fork_share_lock (u32 exit_pid, void *pdata, u16 rec_type)
{
  NSSOC_LOGDBG ("recycle]pid=%u", exit_pid);

  if (g_nstack_share_res.fork_share_lock
      && (g_nstack_share_res.fork_share_lock->lock == exit_pid))
    {
      dmm_spin_unlock (g_nstack_share_res.fork_share_lock);
    }

  return NSFW_RCC_CONTINUE;
}

REGIST_RECYCLE_LOCK_REL (nstack_recycle_fork_share_lock, NULL, NSFW_PROC_APP)
