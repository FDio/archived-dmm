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

#include "nsfw_maintain_api.h"
#include "nstack_securec.h"

u32 g_base_cfg_items[MAX_BASE_CFG] = { 0 };

u32 g_custom_cfg_items[MAX_CUSTOM_CFG] = { 0 };

u32 g_macro_custom_cfg_items[CFG_ITEM_MACRO_CUSTOM_MAX] = { 0 };

struct cfg_item_info g_cfg_item_info[CFG_SEG_MAX][MAX_CFG_ITEM];

u32 get_cfg_info(int tag, int item)
{
    return (u32) g_cfg_item_info[tag][item].value;
}

u32 get_cfg_share_mem_size()
{
    return sizeof(g_base_cfg_items) + sizeof(g_custom_cfg_items) +
        sizeof(g_macro_custom_cfg_items);
}

int get_share_cfg_from_mem(void *mem)
{
    if (EOK !=
        memcpy_s(g_base_cfg_items, sizeof(g_base_cfg_items), mem,
                 sizeof(g_base_cfg_items)))
    {
        return -1;
    }

    char *custom_cfg_mem = (char *) mem + sizeof(g_base_cfg_items);
    if (EOK !=
        memcpy_s(g_custom_cfg_items, sizeof(g_custom_cfg_items),
                 custom_cfg_mem, sizeof(g_custom_cfg_items)))
    {
        return -1;
    }

    char *macro_cfg_mem = custom_cfg_mem + sizeof(g_custom_cfg_items);
    if (EOK !=
        memcpy_s(g_macro_custom_cfg_items, sizeof(g_macro_custom_cfg_items),
                 macro_cfg_mem, sizeof(g_macro_custom_cfg_items)))
    {
        return -1;
    }

    return 0;
}

void get_default_base_cfg(u32 thread_num)
{
    g_base_cfg_items[CFG_BASE_THREAD_NUM] = thread_num;
    g_base_cfg_items[CFG_BASE_RING_SIZE] = DEF_RING_BASE_SIZE;
    g_base_cfg_items[CFG_BASE_HAL_PORT_NUM] = DEF_HAL_PORT_NUM;

    g_base_cfg_items[CFG_BASE_SOCKET_NUM] = 1024;
    g_base_cfg_items[CFG_BASE_ARP_STALE_TIME] = DEF_ARP_STACLE_TIME;
    g_base_cfg_items[CFG_BASE_ARP_BC_RETRANS_NUM] = DEF_ARP_BC_RETRANS_NUM;

    return;
}
