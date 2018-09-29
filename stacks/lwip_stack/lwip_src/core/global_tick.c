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

#include "nsfw_mem_api.h"
#include "global_tick.h"
#include "nstack_securec.h"
#include "nstack_share_res.h"

/** global timer tick */
nstack_tick_info_t g_nstack_timer_tick;

int
init_stackx_global_tick (void)
{
  nsfw_mem_zone mzone;

  if (STRCPY_S
      (mzone.stname.aname, NSFW_MEM_NAME_LENGTH, NSTACK_GLOBAL_TICK_SHM) != 0)
    {
      NSPOL_LOGERR ("STRCPY_S fail");
      return -1;
    }

  mzone.stname.entype = NSFW_SHMEM;
  mzone.isocket_id = -1;
  mzone.length = sizeof (uint64_t);
  mzone.ireserv = 0;

  g_nstack_timer_tick.tick_ptr = (uint64_t *) nsfw_mem_zone_create (&mzone);
  if (NULL == g_nstack_timer_tick.tick_ptr)
    {
      NSPOL_LOGERR ("Failed to create global timer tick memory");
      return -1;
    }

  return 0;
}

int
nstack_lookup_share_global_tick ()
{
  int ret;
  nsfw_mem_name name = {.entype = NSFW_SHMEM,.enowner = NSFW_PROC_MAIN };

  ret = STRCPY_S (name.aname, NSFW_MEM_NAME_LENGTH, NSTACK_GLOBAL_TICK_SHM);
  if (EOK != ret)
    {
      NSSOC_LOGERR ("STRCPY_S failed]name=%s,ret=%d", NSTACK_GLOBAL_TICK_SHM,
                    ret);
      return -1;
    }

  g_nstack_timer_tick.tick_ptr = (uint64_t *) nsfw_mem_zone_lookup (&name);
  if (NULL == g_nstack_timer_tick.tick_ptr)
    {
      NSPOL_LOGERR ("Failed to lookup global timer tick memory");
      return -1;
    }

  NSSOC_LOGDBG ("ok");
  return 0;
}
