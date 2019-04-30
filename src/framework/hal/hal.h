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

#ifndef _HAL_H_
#define _HAL_H_

#include <stdint.h>
#include "nsfw_hal_api.h"

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
#endif

#define HAL_DRV_MAX   32

#define HAL_MAX_PCI_ADDR_LEN 16

#define HAL_SCRIPT_LENGTH       256

#define HAL_HDL_TO_ID(hdl) (hdl.id)

extern netif_inst_t netif_tbl[HAL_MAX_NIC_NUM];

static inline netif_inst_t *alloc_netif_inst()
{
    int i;
    netif_inst_t *inst;

    for (i = 0; i < HAL_MAX_NIC_NUM; ++i)
    {
        inst = &netif_tbl[i];

        if (NETIF_STATE_FREE == inst->state)
        {
            inst->state = NETIF_STATE_ACTIVE;

            inst->hdl.id = i;

            return inst;
        }
    }

    return NULL;

}

static inline netif_inst_t *get_netif_inst(hal_hdl_t hdl)
{
    netif_inst_t *inst;

    if (unlikely(!hal_is_valid(hdl)))
    {
        NSHAL_LOGERR("inst id is not valid]inst=%i, HAL_MAX_NIC_NUM=%d",
                     HAL_HDL_TO_ID(hdl), HAL_MAX_NIC_NUM);

        return NULL;
    }

    inst = &netif_tbl[HAL_HDL_TO_ID(hdl)];

    if (unlikely((NETIF_STATE_ACTIVE != inst->state) || (NULL == inst->ops)))
    {
        NSHAL_LOGERR("netif is not active]inst=%i", HAL_HDL_TO_ID(hdl));

        return NULL;
    }

    return inst;
}

static inline netif_inst_t *get_netif_inst_by_name(const char *name)
{
    int i;
    netif_inst_t *inst;

    if (!name)
    {
        return NULL;
    }

    for (i = 0; i < HAL_MAX_NIC_NUM; ++i)
    {
        inst = &netif_tbl[i];

        if (NETIF_STATE_ACTIVE == inst->state
            && 0 == strncmp(name, inst->data.dpdk_if.nic_name,
                            HAL_MAX_NIC_NAME_LEN))
        {
            return inst;
        }
    }

    return NULL;

}

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif
