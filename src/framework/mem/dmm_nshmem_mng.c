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

#include<stdlib.h>
#include "nsfw_mem_api.h"
#include "dmm_ring.h"
#include "dmm_memory.h"
#include "dmm_nshmem_mng.h"

i32 dmm_nshmem_init(nsfw_mem_para * para)
{
    return NSFW_MEM_OK;
}

/*
 * memory destory
 */
void dmm_nshmem_destory(void)
{
    return;
}

mzone_handle dmm_nshmem_create(nsfw_mem_zone * pinfo)
{
    if (!pinfo->lenth)
    {
        return NULL;
    }
    return calloc(1, pinfo->lenth);
}

mring_handle dmm_nshmem_spcreate(nsfw_mem_sppool * pmpinfo)
{
    struct dmm_ring *ring;

    ring =
        dmm_malloc_pool(pmpinfo->useltsize, (int) pmpinfo->usnum,
                        DMM_RING_INIT_MPMC);
    if (ring == NULL)
    {
        NSSOC_LOGERR("nshmem sp create faild num:%u eltsize:%u",
                     pmpinfo->usnum, pmpinfo->useltsize);
        return NULL;
    }
    return (mring_handle) (ring);
}

i32 dmm_nshmem_sprelease(nsfw_mem_name * pname)
{
    return NSFW_MEM_OK;
}

mring_handle dmm_nshmem_ringcreate(nsfw_mem_mring * pringinfo)
{
    struct dmm_ring *ring = NULL;

    ring = dmm_malloc_ring((int) pringinfo->usnum, DMM_RING_INIT_MPMC);
    if (ring == NULL)
    {
        NSSOC_LOGERR("nshmem ring create faild num:%u", pringinfo->usnum);
        return NULL;
    }
    return (mring_handle) (ring);
}

i32 dmm_nshmem_ringrelease(nsfw_mem_name * pname)
{
    return NSFW_MEM_OK;
}

ssize_t dmm_nshmem_sppool_statics(mring_handle sppool)
{
    size_t size = 0;
    struct dmm_ring *ring = (struct dmm_ring *) sppool;
    if (ring == NULL)
    {
        NSSOC_LOGERR("nshmem sppool stat para errer");
        return 0;
    }

    size = dmm_ring_bufsize(ring->size - 1);
    size = size + dmm_pool_arraysize((ring->size - 1), ring->eltsize);

    return size;
}

ssize_t dmm_nshmem_ring_statics(mring_handle handle)
{
    struct dmm_ring *ring = (struct dmm_ring *) handle;
    if (ring == NULL)
    {
        NSSOC_LOGERR("nshmem ring stat para errer");
        return 0;
    }

    return dmm_ring_bufsize(ring->size - 1);
}

ssize_t dmm_nshmem_stactic(void *handle, nsfw_mem_struct_type type)
{
    switch (type)
    {
        case NSFW_MEM_MBUF:
            return -1;
        case NSFW_MEM_SPOOL:
            return dmm_nshmem_sppool_statics(handle);
        case NSFW_MEM_RING:
            return dmm_nshmem_ring_statics(handle);
        default:
            break;
    }
    return -1;
}
