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
#include "dmm_memory.h"
#include "dmm_ring.h"
#include "dmm_shmem_mng.h"
#include "nstack_securec.h"

/*
 *share memory mng module init
 *
 */
i32 dmm_shmem_init(nsfw_mem_para * para)
{
    i32 iret = NSFW_MEM_OK;

    NSSOC_LOGINF("shmem init begin");

    if (NSFW_PROC_APP != para->enflag)
    {
        NSSOC_LOGERR("shmem init with error proc type");
        return NSFW_MEM_ERR;
    }
    else
    {
        iret = dmm_mem_module_init((void *) ((u64) (para->enflag)));
    }

    if (NSFW_MEM_OK != iret)
    {
        NSSOC_LOGERR("shmem init fail]ret=0x%x", iret);
        return NSFW_MEM_RTP_FAIL;
    }

    NSRTP_LOGINF("shmem init end]flag=%d", para->enflag);
    return NSFW_MEM_OK;
}

/*
 *module destroy
 */
void dmm_shmem_destroy(void)
{
    (void) dmm_share_destroy();

    return;
}

/*
 * create a shared memory
 * nsfw_mem_zone::stname memory name
 * nsfw_mem_zone::isize
 */
mzone_handle dmm_shmem_create(nsfw_mem_zone * pinfo)
{
    return dmm_locked_map(pinfo->lenth, pinfo->stname.aname);
}

/*
 *create some memory
 *inum must be equal iarray_num
 */
i32 dmm_shmem_createv(nsfw_mem_zone * pmeminfo, i32 inum,
                      mzone_handle * paddr_array, i32 iarray_num)
{
    return NSFW_MEM_OK;
}

mzone_handle dmm_shmem_lookup(nsfw_mem_name * pname)
{
    return dmm_lookup(pname->aname);
}

i32 dmm_shmem_release(nsfw_mem_name * pname)
{
    void *ptr = NULL;

    ptr = dmm_lookup(pname->aname);
    if (ptr == NULL)
    {
        NSSOC_LOGERR("shmem[%s] release fail", pname->aname);
        return NSFW_MEM_ERR;
    }

    return dmm_unmap(ptr);
}

mpool_handle dmm_shmem_mbfmpcreate(nsfw_mem_mbfpool * pbufinfo)
{
    return NULL;
}

/*
 *create some mbuf pools
 */
i32 dmm_shmem_mbfmpcreatev(nsfw_mem_mbfpool * pmbfname, i32 inum,
                           mpool_handle * phandle_array, i32 iarray_num)
{
    return 0;
}

mpool_handle dmm_shmem_mbfmplookup(nsfw_mem_name * pmbfname)
{
    return NULL;
}

i32 dmm_shmem_mbfmprelease(nsfw_mem_name * pname)
{
    return NSFW_MEM_OK;
}

mring_handle dmm_shmem_spcreate(nsfw_mem_sppool * pmpinfo)
{
    struct dmm_ring *ring;

    ring =
        dmm_create_pool(pmpinfo->useltsize, (int) pmpinfo->usnum,
                        DMM_RING_INIT_MPMC, pmpinfo->stname.aname);
    if (ring == NULL)
    {
        NSSOC_LOGERR("shmem sp create faild num:%u eltsize:%u",
                     pmpinfo->usnum, pmpinfo->useltsize);
        return NULL;
    }

    return (mring_handle) (ring);
}

i32 dmm_shmem_spcreatev(nsfw_mem_sppool * pmpinfo, i32 inum,
                        mring_handle * pringhandle_array, i32 iarray_num)
{
    return NSFW_MEM_OK;
}

i32 dmm_shmem_sp_ringcreate(nsfw_mem_mring * prpoolinfo,
                            mring_handle * pringhandle_array, i32 iringnum)
{
    i32 i = 0;
    size_t eltsize = 0;
    mring_handle ring = NULL;
    size_t ring_size = 0;
    nsfw_mem_sppool mpinfo;
    char *pool = NULL;

    eltsize = dmm_ring_bufsize((int) prpoolinfo->usnum);
    mpinfo.useltsize = eltsize;
    mpinfo.usnum = iringnum;
    (void) strncpy_s(mpinfo.stname.aname, sizeof(mpinfo.stname.aname),
                     prpoolinfo->stname.aname,
                     sizeof(mpinfo.stname.aname) - 1);

    ring = dmm_shmem_spcreate(&mpinfo);
    if (ring == NULL)
    {
        NSSOC_LOGERR("shmem spring create faild num:%u eltsize:%u",
                     mpinfo.usnum, mpinfo.useltsize);
        return NSFW_MEM_ERR;
    }

    ring_size = dmm_ring_bufsize(iringnum);
    pool = (char *) ring + ring_size;
    for (i = 0; i < iringnum; i++)
    {
        pringhandle_array[i] = pool;
        if (0 !=
            dmm_ring_init((struct dmm_ring *) pringhandle_array[i],
                          (int) prpoolinfo->usnum, eltsize,
                          DMM_RING_INIT_MPMC, NSFW_SHMEM))
        {
            NSSOC_LOGERR("ring init faild index:%d", i);
            return NSFW_MEM_ERR;
        }
        pool = pool + eltsize;
    }

    return NSFW_MEM_OK;
}

i32 dmm_shmem_sprelease(nsfw_mem_name * pname)
{
    return dmm_shmem_release(pname);
}

mring_handle dmm_shmem_sp_lookup(nsfw_mem_name * pname)
{
    return dmm_lookup(pname->aname);
}

mring_handle dmm_shmem_ringcreate(nsfw_mem_mring * pringinfo)
{
    struct dmm_ring *ring;

    ring =
        dmm_create_ring((int) pringinfo->usnum, DMM_RING_INIT_MPMC,
                        pringinfo->stname.aname);

    return (mring_handle) (ring);
}

mring_handle dmm_shmem_ring_lookup(nsfw_mem_name * pname)
{
    return dmm_lookup(pname->aname);
}

i32 dmm_shmem_ringrelease(nsfw_mem_name * pname)
{
    return dmm_shmem_release(pname);
}

size_t dmm_shmem_sppool_statics(mring_handle sppool)
{
    size_t size = 0;
    struct dmm_ring *ring = (struct dmm_ring *) sppool;
    if (ring == NULL)
    {
        NSSOC_LOGERR("shmem sppool stat para errer");
        return 0;
    }

    size = dmm_ring_bufsize(ring->size - 1);
    size = size + dmm_pool_arraysize((ring->size - 1), ring->eltsize);

    return size;
}

size_t dmm_shmem_ring_statics(mring_handle handle)
{
    struct dmm_ring *ring = (struct dmm_ring *) handle;
    if (ring == NULL)
    {
        NSSOC_LOGERR("shmem ring stat para errer");
        return 0;
    }

    return dmm_ring_bufsize(ring->size - 1);
}

ssize_t dmm_shmem_stactic(void *handle, nsfw_mem_struct_type type)
{
    switch (type)
    {
        case NSFW_MEM_MBUF:
            return 0;
        case NSFW_MEM_SPOOL:
            return dmm_shmem_sppool_statics(handle);
        case NSFW_MEM_RING:
            return dmm_shmem_ring_statics(handle);
        default:
            break;
    }
    return -1;
}

i32 dmm_shmem_sp_iterator(mpool_handle handle, u32 start, u32 end,
                          nsfw_mem_item_fun fun, void *argv)
{
    return 0;
}

void *dmm_shmem_shddr_to_laddr(void *addr)
{
    return addr;
}

uint64_t dmm_shmem_laddr_to_shddr(void *addr)
{
    return (uint64_t) (addr);
}

int dmm_attach_core_id(nsfw_mem_name * name)
{
    return 0;
}
