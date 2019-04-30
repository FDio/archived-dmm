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

#include <stdlib.h>
#include "types.h"
#include "nstack_securec.h"
#include "nsfw_init_api.h"

#include "nstack_log.h"
#include "nsfw_maintain_api.h"

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C"{
/* *INDENT-ON* */
#endif /* __cplusplus */

nsfw_res_mgr_item_cfg g_all_res_can[NSFW_MAX_RES_SCAN_COUNT];

u8 nsfw_res_mgr_reg(nsfw_res_scn_cfg * cfg)
{
    if (NULL == cfg)
    {
        NSFW_LOGERR("argv err!");
        return FALSE;
    }

    u32 i;
    for (i = 0; i < NSFW_MAX_RES_SCAN_COUNT; i++)
    {

        if ((NULL == g_all_res_can[i].scn_cfg.free_fun)
            &&
            (__sync_bool_compare_and_swap
             (&g_all_res_can[i].scn_cfg.free_fun, 0, cfg->free_fun)))
        {
            g_all_res_can[i].scn_cfg = *cfg;
            NSFW_LOGINF("reg res_mgr fun suc]fun=%p,data=%p", cfg->free_fun,
                        cfg->data);
            return TRUE;
        }
    }

    /* here is fail branch, should log ERR level and return false */
    NSFW_LOGERR
        ("reg]type=%u,per=%u,chk=%u,cyc=%u,total=%u,size=%u,offset=%u,fun=%p,data=%p",
         cfg->type, cfg->force_free_percent, cfg->force_free_chk_num,
         cfg->num_per_cyc, cfg->total_num, cfg->elm_size, cfg->res_mem_offset,
         cfg->free_fun, cfg->data);
    return FALSE;
}

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif /* __cplusplus */
