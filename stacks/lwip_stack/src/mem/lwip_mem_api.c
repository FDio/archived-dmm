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

#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>
#include "nsfw_mem_api.h"
#include "nstack_securec.h"
#include "nsfw_ring_data.h"
#include "nsfw_init_api.h"
#include "nsfw_shmem_mng.h"

#define NSFW_MEM_MBUF_CHECK_RET_ERR(mhandle, entype, desc)  {\
        if ((NULL == mhandle) || (entype >= NSFW_MEM_TYPEMAX)) \
        { \
            NSRTP_LOGERR("input para error]desc=%s,mhandle=%p,mtype=%d", desc, mhandle, entype); \
            return NSFW_MEM_ERR; \
        } \
    }

#define NSFW_MEM_MBUF_CHECK_RET_NULL(mhandle, entype, desc)  {\
        if ((NULL == mhandle) || (entype >= NSFW_MEM_TYPEMAX)) \
        { \
            NSRTP_LOGERR("input para error]desc=%s,mhandle=%p,mtype=%d", desc, mhandle, entype); \
            return NULL; \
        } \
    }

/*****************************************************************************
*   Prototype    : nsfw_mem_mbf_alloc
*   Description  : alloc a mbuf from mbuf pool
*   Input        : mpool_handle mhandle
*                  nsfw_mem_type entype
*   Output       : None
*   Return Value : mbuf_handle
*   Calls        :
*   Called By    :
*****************************************************************************/
mbuf_handle nsfw_mem_mbf_alloc(mpool_handle mhandle, nsfw_mem_type entype)
{
    if (entype == NSFW_SHMEM)
    {
        return nsfw_shmem_mbfalloc(mhandle);
    }

    NSPOL_LOGINF(NS_LOG_STACKPOOL_ON, "mbf alloc fail] handle=%p, type=%d",
                 mhandle, entype);
    return NULL;
}

/*****************************************************************************
*   Prototype    : nsfw_mem_mbf_free
*   Description  : put a mbuf backintp mbuf pool
*   Input        : mbuf_handle mhandle
*                  nsfw_mem_type entype
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*
*****************************************************************************/
i32 nsfw_mem_mbf_free(mbuf_handle mhandle, nsfw_mem_type entype)
{
    if (entype == NSFW_SHMEM)
    {
        return nsfw_shmem_mbffree(mhandle);
    }

    NSPOL_LOGINF(NS_LOG_STACKPOOL_ON, "mbf free fail] handle=%p, type=%d",
                 mhandle, entype);
    return NSFW_MEM_ERR;

}
