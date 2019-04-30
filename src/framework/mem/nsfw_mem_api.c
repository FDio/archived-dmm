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

#define MEM_OP_CALL_OK_RET(mtype, fun, para) { \
        if (g_nsfw_mem_ops[mtype].stmemop->fun) \
        { \
            return g_nsfw_mem_ops[mtype].stmemop->fun para; \
        } \
    }
#define NSFW_MEM_NAME_CHECK_RET_ERR(pname, desc)  {\
        if ((NULL == (pname)) || ((pname)->entype >= NSFW_MEM_TYPEMAX)) \
        { \
            NSRTP_LOGERR("input para error]desc=%s,pname=%p,mtype=%d", desc, pname, (pname) ? (pname)->entype:-1); \
            return NSFW_MEM_ERR;  \
        }  \
    }

#define NSFW_MEM_NAME_CHECK_RET_NULL(pname, desc)  {\
        if ((NULL == (pname)) || ((pname)->entype >= NSFW_MEM_TYPEMAX)) \
        { \
            NSRTP_LOGERR("input para error]desc=%s,pname=%p,mtype=%d", desc, pname, (pname) ? (pname)->entype:-1); \
            return NULL;  \
        }  \
    }

#define NSFW_MEM_RING_CHECK_RET(pringinfo, pringhandle_array, iringnum)  {\
        if ((NULL == pringinfo) || (NULL == pringhandle_array) || (pringinfo[0].stname.entype >= NSFW_MEM_TYPEMAX)) \
        {  \
            NSRTP_LOGERR("input para error]pringinfo=%p,iringnum=%d,pringhandle_array=%p,mtype=%d",  \
                         pringinfo, iringnum, pringhandle_array, pringinfo ? pringinfo[0].stname.entype : (-1));  \
            return NSFW_MEM_ERR;  \
        }  \
    }

#define NSFW_MEM_RINGV_CHECK_RET(pmpinfo, inum, pringhandle_array, iarray_num)  { \
        if ((NULL == pmpinfo) || (NULL == pringhandle_array)  \
            || (inum != iarray_num) || (inum <= 0) || (pmpinfo[0].stname.entype >= NSFW_MEM_TYPEMAX)) \
        {   \
            NSRTP_LOGERR("input para error]pmpinfo=%p,inum=%d,pringhandle_array=%p,iarray_num=%d,entype=%d", \
                         pmpinfo, inum, pringhandle_array, iarray_num, pmpinfo ? pmpinfo[0].stname.entype : (-1));  \
            return NSFW_MEM_ERR;  \
        }  \
    }

#ifndef FOR_ATTACH_COREID
/*
 * attach core id when malloc resource
 */
static int nsfw_attach_core_id(nsfw_mem_name * name)
{
    MEM_OP_CALL_OK_RET(NSFW_SHMEM, mem_ops_attach_core_id, (name));
    NSRTP_LOGINF
        ("nsfw_attach_core_id failed]field mem_ops_attach_core_id is NULL");
    return -1;
}
#endif

i32 nsfw_mem_init(void *para)
{
    nsfw_mem_para *ptempara = NULL;
    i32 iret = NSFW_MEM_OK;
    i32 icount = 0;
    i32 iindex = 0;

    if (NULL == para)
    {
        NSRTP_LOGERR("ns mem init input error");
        return NSFW_MEM_ERR;
    }

    ptempara = (nsfw_mem_para *) para;

    if (ptempara->enflag >= NSFW_PROC_MAX)
    {
        NSRTP_LOGERR("ns mem init input enflag invalid]enflag=%d",
                     ptempara->enflag);
        return NSFW_MEM_ERR;
    }

    NSRTP_LOGINF("ns mem init begin]enflag=%d,iargsnum=%d", ptempara->enflag,
                 ptempara->iargsnum);

    for (iindex = 0; iindex < ptempara->iargsnum; iindex++)
    {
        NSRTP_LOGINF("%s", ptempara->pargs[iindex]);
    }

    for (icount = 0; icount < g_mem_type_num; icount++)
    {
        if ((NULL != g_nsfw_mem_ops[icount].stmemop)
            && (NULL != g_nsfw_mem_ops[icount].stmemop->mem_ops_init))
        {
            iret = g_nsfw_mem_ops[icount].stmemop->mem_ops_init(ptempara);

            if (NSFW_MEM_OK != iret)
            {
                NSRTP_LOGERR("mem init failed]index=%d,memtype=%d", icount,
                             g_nsfw_mem_ops[icount].entype);
                break;
            }
        }
    }

    /* if some module init fail, destory the modules that succeeded */
    if (icount < g_mem_type_num)
    {
        for (iindex = 0; iindex < icount; iindex++)
        {
            if (g_nsfw_mem_ops[icount].stmemop->mem_ops_destroy)
            {
                g_nsfw_mem_ops[icount].stmemop->mem_ops_destroy();
            }
        }

        return iret;            /* return errcode to caller */
    }

    NSRTP_LOGINF("mem init end");
    return NSFW_MEM_OK;
}

/*****************************************************************************
*   Prototype    : nsfw_mem_zone_create
*   Description  : create a block memory with name
*                  nsfw_mem_zone::stname
*                  nsfw_mem_zone::isize
*   note         : 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
*   Input        : nsfw_mem_zone* pinfo
*   Output       : None
*   Return Value : mzone_handle
*   Calls        :
*   Called By    :
*****************************************************************************/
mzone_handle nsfw_mem_zone_create(nsfw_mem_zone * pinfo)
{
    if ((NULL == pinfo) || (pinfo->stname.entype >= NSFW_MEM_TYPEMAX))
    {
        NSRTP_LOGERR("zone create input para error] pinfo=%p, mtype=%d",
                     pinfo, pinfo ? pinfo->stname.entype : (-1));
        return NULL;
    }

#ifndef FOR_ATTACH_COREID
    if (nsfw_attach_core_id(&pinfo->stname) != 0)
    {
        return NULL;
    }
#endif

    MEM_OP_CALL_OK_RET(pinfo->stname.entype, mem_ops_zone_creae, (pinfo));
    NSRTP_LOGINF("mem create fail] memtype=%d, name=%s, size=%zu",
                 pinfo->stname.entype, pinfo->stname.aname, pinfo->lenth);
    return NULL;
}

/*****************************************************************************
*   Prototype    : nsfw_mem_zone_createv
*   Description  : create some memory blocks
*   note         : 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
*   Input        : nsfw_mem_zone* pmeminfo
*                  i32 inum
*                  mzone_handle* paddr_array
*                  i32 iarray_num
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 nsfw_mem_zone_createv(nsfw_mem_zone * pmeminfo, i32 inum,
                          mzone_handle * paddr_array, i32 iarray_num)
{
    if ((NULL == pmeminfo) || (NULL == paddr_array)
        || (inum != iarray_num) || (inum <= 0)
        || (pmeminfo[0].stname.entype >= NSFW_MEM_TYPEMAX))
    {
        NSRTP_LOGERR
            ("input para error] pmeminfo=%p, inum=%d, paddr_array=%p, iarray_num=%d, mtype=%d",
             pmeminfo, inum, paddr_array, iarray_num,
             pmeminfo ? pmeminfo[0].stname.entype : (-1));
        return NSFW_MEM_ERR;
    }

#ifndef FOR_ATTACH_COREID
    i32 i;
    for (i = 0; i < inum; ++i)
    {
        if (nsfw_attach_core_id(&pmeminfo[i].stname) != 0)
        {
            return NSFW_MEM_ERR;
        }
    }
#endif

    MEM_OP_CALL_OK_RET(pmeminfo[0].stname.entype, mem_ops_zone_createv,
                       (pmeminfo, inum, paddr_array, iarray_num));
    NSRTP_LOGINF("mem create fail] memtype=%d", pmeminfo[0].stname.entype);
    return NSFW_MEM_ERR;
}

/*****************************************************************************
*   Prototype    : nsfw_mem_zone_lookup
*   Description  : look up a memory
*                  1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
*                  2. if the memory is shared, pname->enowner indicate that who create this memory.
*   note         : 1. when calling any shared memory create inferface, the name of memory end with _0 created by daemon-stack,
*                     end with none created by nStackMaster, and end with _<pid> created by other.
*                  2. pname->enowner is available only when call look up shared memory.
*                  3. if the roles of process is NSFW_PROC_MASTER but the memory was created by others, or pname->enowner is NSFW_PROC_NULL,
*                     the name must be full name.
*                     for examles if the memory was created by daemon-stack and pname->enowner is NSFW_PROC_NULL,
*                     must add '_0' at the end of name, if the memory was created by app and the role of process is NSFW_PROC_MASTER, must add
*                     _(pid) at the end of name, nstack_123.
*   Input        : nsfw_mem_name* pname
*   Output       : None
*   Return Value : mzone_handle
*   Calls        :
*   Called By    :
*****************************************************************************/
mzone_handle nsfw_mem_zone_lookup(nsfw_mem_name * pname)
{
    NSFW_MEM_NAME_CHECK_RET_NULL(pname, "mem zone look up");

#ifndef FOR_ATTACH_COREID
    if (nsfw_attach_core_id(pname) != 0)
    {
        return NULL;
    }
#endif

    MEM_OP_CALL_OK_RET(pname->entype, mem_ops_zone_lookup, (pname));
    NSRTP_LOGERR("mem lookup fail] memtype=%d, name=%s ", pname->entype,
                 pname->aname);
    return NULL;
}

i32 nsfw_mem_zone_release(nsfw_mem_name * pname)
{
    NSFW_MEM_NAME_CHECK_RET_ERR(pname, "mem zone release");

#ifndef FOR_ATTACH_COREID
    if (nsfw_attach_core_id(pname) != 0)
    {
        return NSFW_MEM_ERR;
    }
#endif

    MEM_OP_CALL_OK_RET(pname->entype, mem_ops_mzone_release, (pname));
    NSRTP_LOGERR("mem release fail] memtype=%d, name=%s", pname->entype,
                 pname->aname);
    return NSFW_MEM_ERR;

}

/*****************************************************************************
*   Prototype    : nsfw_mem_mbfmp_create
*   Description  : create a mbuf pool
*   Input        : nsfw_mem_mbfpool* pbufinfo
*   Output       : None
*   Return Value : mpool_handle
*   Calls        :
*   Called By    :
*****************************************************************************/
mpool_handle nsfw_mem_mbfmp_create(nsfw_mem_mbfpool * pbufinfo)
{
    if ((NULL == pbufinfo) || (pbufinfo->stname.entype >= NSFW_MEM_TYPEMAX))
    {
        NSRTP_LOGERR("input para error] pbufinfo=%p, mtype=%d", pbufinfo,
                     pbufinfo ? pbufinfo->stname.entype : (-1));
        return NULL;
    }

#ifndef FOR_ATTACH_COREID
    if (nsfw_attach_core_id(&pbufinfo->stname) != 0)
    {
        return NULL;
    }
#endif

    MEM_OP_CALL_OK_RET(pbufinfo->stname.entype, mem_ops_mbfmp_create,
                       (pbufinfo));
    NSRTP_LOGERR("mbufmp create fail] memtype=%d, name=%s ",
                 pbufinfo->stname.entype, pbufinfo->stname.aname);
    return NULL;
}

/*****************************************************************************
*   Prototype    : nsfw_mem_mbfmp_createv
*   Description  : create some mbuf pools
*                  1. the name of lenth must be less than NSFW_MEM_APPNAME_LENTH.
*   Input        : nsfw_mem_mbfpool* pmbfname
*                  i32 inum
*                  mpool_handle* phandle_array
*                  i32 iarray_num
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 nsfw_mem_mbfmp_createv(nsfw_mem_mbfpool * pmbfname, i32 inum,
                           mpool_handle * phandle_array, i32 iarray_num)
{
    if ((NULL == pmbfname) || (NULL == phandle_array)
        || (inum != iarray_num) || (inum <= 0)
        || (pmbfname[0].stname.entype >= NSFW_MEM_TYPEMAX))
    {
        NSRTP_LOGERR
            ("input para error] pmbfname=%p, inum=%d, phandle_array=%p, iarray_num=%d,entype=%d",
             pmbfname, inum, phandle_array, iarray_num,
             pmbfname ? pmbfname[0].stname.entype : (-1));
        return NSFW_MEM_ERR;
    }

#ifndef FOR_ATTACH_COREID
    i32 i;
    for (i = 0; i < inum; ++i)
    {
        if (nsfw_attach_core_id(&pmbfname[i].stname) != 0)
        {
            return NSFW_MEM_ERR;
        }
    }
#endif

    MEM_OP_CALL_OK_RET(pmbfname[0].stname.entype, mem_ops_mbfmp_createv,
                       (pmbfname, inum, phandle_array, iarray_num));
    NSRTP_LOGERR("mbufmp createv fail] memtype=%d",
                 pmbfname[0].stname.entype);
    return NSFW_MEM_ERR;
}

/*****************************************************************************
*   Prototype    : nsfw_mem_mbfmp_lookup
*   Description  : look up mbuf mpool
*                  1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
*                  2. if the memory is shared, pname->enowner indicate that who create this memory.
*   note         : 1. when calling any shared memory create inferface, the name of memory end with _0 created by daemon-stack,
*                     end with none created by nStackMaster, and end with _<pid> created by other.
*                  2. pname->enowner is available only when call look up shared memory.
*                  3. if the roles of process is NSFW_PROC_MASTER but the memory was created by others, or pname->enowner is NSFW_PROC_NULL,
*                     the name must be full name.
*                     for examles if the memory was created by daemon-stack and pname->enowner is NSFW_PROC_NULL,
*                     must add '_0' at the end of name, if the memory was created by app and the role of process is NSFW_PROC_MASTER, must add
*                     _(pid) at the end of name, nstack_123.
*   Input        : nsfw_mem_name* pmbfname
*   Output       : None
*   Return Value : mpool_handle
*   Calls        :
*   Called By    :
*****************************************************************************/
mpool_handle nsfw_mem_mbfmp_lookup(nsfw_mem_name * pmbfname)
{
    NSFW_MEM_NAME_CHECK_RET_NULL(pmbfname, "mbuf pool look up");

#ifndef FOR_ATTACH_COREID
    if (nsfw_attach_core_id(pmbfname) != 0)
    {
        return NULL;
    }
#endif

    MEM_OP_CALL_OK_RET(pmbfname->entype, mem_ops_mbfmp_lookup, (pmbfname));
    NSRTP_LOGERR("mbufmp lookup fail] memtype=%d, name=%s ",
                 pmbfname->entype, pmbfname->aname);
    return NULL;
}

/*****************************************************************************
*   Prototype    : nsfw_mem_mbfmp_release
*   Description  : release mbuf pool
*   note         : 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
*   Input        : nsfw_mem_name* pname
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 nsfw_mem_mbfmp_release(nsfw_mem_name * pname)
{
    NSFW_MEM_NAME_CHECK_RET_ERR(pname, "mbuf mp release");

#ifndef FOR_ATTACH_COREID
    if (nsfw_attach_core_id(pname) != 0)
    {
        return NSFW_MEM_ERR;
    }
#endif

    MEM_OP_CALL_OK_RET(pname->entype, mem_ops_mbfmp_release, (pname));
    NSRTP_LOGERR("mbfmp release fail] memtype=%d, name=%s", pname->entype,
                 pname->aname);
    return NSFW_MEM_ERR;
}

/*****************************************************************************
*   Prototype    : nsfw_mem_sp_create
*   Description  : create a simple pool
*   note         : 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
*   Input        : nsfw_mem_sppool* pmpinfo
*   Output       : None
*   Return Value : mring_handle
*   Calls        :
*   Called By    :
*****************************************************************************/
mring_handle nsfw_mem_sp_create(nsfw_mem_sppool * pmpinfo)
{
    if ((NULL == pmpinfo) || (pmpinfo->stname.entype >= NSFW_MEM_TYPEMAX))
    {
        NSRTP_LOGERR("input para error] pmpinfo=%p, mtype=%d", pmpinfo,
                     pmpinfo ? pmpinfo->stname.entype : (-1));
        return NULL;
    }

#ifndef FOR_ATTACH_COREID
    if (nsfw_attach_core_id(&pmpinfo->stname) != 0)
    {
        return NULL;
    }
#endif

    MEM_OP_CALL_OK_RET(pmpinfo->stname.entype, mem_ops_sp_create, (pmpinfo));
    NSRTP_LOGERR("sp create fail] memtype=%d, name=%s ",
                 pmpinfo->stname.entype, pmpinfo->stname.aname);
    return NULL;

}

/*****************************************************************************
*   Prototype    : nsfw_mem_sp_createv
*   Description  : create some simple pools one time
*   note         : 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
*   Input        : nsfw_mem_sppool* pmpinfo
*                  i32 inum
*                  mring_handle* pringhandle_array
*                  i32 iarray_num
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 nsfw_mem_sp_createv(nsfw_mem_sppool * pmpinfo, i32 inum,
                        mring_handle * pringhandle_array, i32 iarray_num)
{
    NSFW_MEM_RINGV_CHECK_RET(pmpinfo, inum, pringhandle_array, iarray_num);

#ifndef FOR_ATTACH_COREID
    i32 i;
    for (i = 0; i < inum; ++i)
    {
        if (nsfw_attach_core_id(&pmpinfo[i].stname) != 0)
        {
            return NSFW_MEM_ERR;
        }
    }
#endif

    MEM_OP_CALL_OK_RET(pmpinfo[0].stname.entype, mem_ops_sp_createv,
                       (pmpinfo, inum, pringhandle_array, iarray_num));
    NSRTP_LOGERR("sp createv fail] memtype=%d", pmpinfo[0].stname.entype);
    return NSFW_MEM_ERR;

}

/*****************************************************************************
*   Prototype    : nsfw_mem_sp_ring_create
*   Description  : create a simple pool with many rings
*   note         : 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
*   Input        : nsfw_mem_mring* pringinfo
*                  mring_handle* pringhandle_array
*                  i32 iringnum
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 nsfw_mem_sp_ring_create(nsfw_mem_mring * pringinfo,
                            mring_handle * pringhandle_array, i32 iringnum)
{
    NSFW_MEM_RING_CHECK_RET(pringinfo, pringhandle_array, iringnum);

#ifndef FOR_ATTACH_COREID
    if (nsfw_attach_core_id(&pringinfo->stname) != 0)
    {
        return NSFW_MEM_ERR;
    }
#endif

    MEM_OP_CALL_OK_RET(pringinfo[0].stname.entype, mem_ops_spring_create,
                       (pringinfo, pringhandle_array, iringnum));
    NSRTP_LOGERR("mppool spring creat fail] memtype=%d",
                 pringinfo[0].stname.entype);
    return NSFW_MEM_ERR;

}

/*****************************************************************************
*   Prototype    : nsfw_mem_sp_release
*   Description  : release a simple mempool
*   note         : 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
*   Input        : nsfw_mem_name* pname
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 nsfw_mem_sp_release(nsfw_mem_name * pname)
{
    NSFW_MEM_NAME_CHECK_RET_ERR(pname, "sp release");

#ifndef FOR_ATTACH_COREID
    if (nsfw_attach_core_id(pname) != 0)
    {
        return NSFW_MEM_ERR;
    }
#endif

    MEM_OP_CALL_OK_RET(pname->entype, mem_ops_sp_release, (pname));
    NSRTP_LOGERR("sp release fail] memtype=%d, name=%s ", pname->entype,
                 pname->aname);
    return NSFW_MEM_ERR;
}

/*****************************************************************************
*   Prototype    : nsfw_mem_sp_lookup
*   Description  : look up a simpile ring
*                  1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
*                  2. if the memory is shared, pname->enowner indicate that who create this memory.
*   note         : 1. when calling any shared memory create inferface, the name of memory end with _0 created by daemon-stack,
*                     end with none created by nStackMaster, and end with _<pid> created by other.
*                  2. pname->enowner is available only when call look up shared memory.
*                  3. if the roles of process is NSFW_PROC_MASTER but the memory was created by others, or pname->enowner is NSFW_PROC_NULL,
*                     the name must be full name.
*                     for examles if the memory was created by daemon-stack and pname->enowner is NSFW_PROC_NULL,
*                     must add '_0' at the end of name, if the memory was created by app and the role of process is NSFW_PROC_MASTER, must add
*                     _(pid) at the end of name, nstack_123.
*   Input        : nsfw_mem_name* pname
*   Output       : None
*   Return Value : mring_handle
*   Calls        :
*   Called By    :
*****************************************************************************/
mring_handle nsfw_mem_sp_lookup(nsfw_mem_name * pname)
{
    NSFW_MEM_NAME_CHECK_RET_NULL(pname, "sp look up");

#ifndef FOR_ATTACH_COREID
    if (nsfw_attach_core_id(pname) != 0)
    {
        return NULL;
    }
#endif

    MEM_OP_CALL_OK_RET(pname->entype, mem_ops_sp_lookup, (pname));
    NSRTP_LOGERR("sp lookup fail] memtype=%d, name=%s", pname->entype,
                 pname->aname);
    return NULL;

}

/*****************************************************************************
*   Prototype    : nsfw_mem_ring_create
*   Description  : create a ring
*   note         : 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
*                  2. shared memory ring (NSFW_SHMEM) just can put a pointor into the queue, the queue also point to a shared block memory.
*                     no shared memory ring(NSFW_NSHMEM) is other wise.
*   Input        : nsfw_mem_mring* pringinfo
*   Output       : None
*   Return Value : mring_handle
*   Calls        :
*   Called By    :
*****************************************************************************/
mring_handle nsfw_mem_ring_create(nsfw_mem_mring * pringinfo)
{
    if ((NULL == pringinfo) || (pringinfo->stname.entype >= NSFW_MEM_TYPEMAX))
    {
        NSRTP_LOGERR("input para error] pmpinfo=%p, mtype=%d", pringinfo,
                     pringinfo ? pringinfo->stname.entype : (-1));
        return NULL;
    }

#ifndef FOR_ATTACH_COREID
    if (nsfw_attach_core_id(&pringinfo->stname) != 0)
    {
        NSRTP_LOGERR
            ("nsfw_attach_core_id failed] type=%d, owner=%d, name=%s",
             pringinfo->stname.entype, pringinfo->stname.enowner,
             pringinfo->stname.aname);
        return NULL;
    }
#endif

    MEM_OP_CALL_OK_RET(pringinfo->stname.entype, mem_ops_ring_create,
                       (pringinfo));
    NSRTP_LOGERR("ring create fail] memtype=%d, name=%s ",
                 pringinfo->stname.entype, pringinfo->stname.aname);
    return NULL;
}

/*****************************************************************************
*   Prototype    : nsfw_mem_ring_lookup
*   Description  : look up a ring by name
*       1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
*       2. if the memory is shared, pname->enowner indicate that who create this memory.
*           note:
*           1. when calling any shared memory create inferface, the name of memory end with _0 created by daemon-stack,
*              end with none created by nStackMaster, and end with _<pid> created by other.
*           2. pname->enowner is available only when call look up shared memory.
*           3. if the roles of process is NSFW_PROC_MASTER but the memory was created by others, or pname->enowner is NSFW_PROC_NULL,
*              the name must be full name.
*              for examles if the memory was created by daemon-stack and pname->enowner is NSFW_PROC_NULL,
*              must add '_0' at the end of name, if the memory was created by app and the role of process is NSFW_PROC_MASTER, must add
*              _(pid) at the end of name, nstack_123.
*   Input        : nsfw_mem_name* pname
*   Output       : None
*   Return Value : mring_handle
*   Calls        :
*   Called By    :
*****************************************************************************/
mring_handle nsfw_mem_ring_lookup(nsfw_mem_name * pname)
{
    NSFW_MEM_NAME_CHECK_RET_NULL(pname, "ring lookup");

#ifndef FOR_ATTACH_COREID
    if (nsfw_attach_core_id(pname) != 0)
    {
        return NULL;
    }
#endif

    MEM_OP_CALL_OK_RET(pname->entype, mem_ops_ring_lookup, (pname));
    NSRTP_LOGERR("ring lookup fail] memtype=%d, name=%s", pname->entype,
                 pname->aname);
    return NULL;
}

/*****************************************************************************
*   Prototype    : nsfw_mem_ring_reset
*   Description  : reset the number of producer and consumer, also, the
*                  state of ring reset to empty
*   notes        : must be called before doing any operations base on the ring
*   Input        : mring_handle mhandle
*                  nsfw_mpool_type entype
*   Output       : None
*   Return Value : void
*   Calls        :
*   Called By    :
*****************************************************************************/
void nsfw_mem_ring_reset(mring_handle mhandle, nsfw_mpool_type entype)
{
    u32 loop = 0;
    struct nsfw_mem_ring *ring = (struct nsfw_mem_ring *) mhandle;

    if (!ring)
    {
        return;
    }

    ring->prod.head = 0;
    ring->cons.tail = 0;
    ring->ringflag = (u8) entype;

    /*init Ring */
    for (loop = 0; loop < ring->size; loop++)
    {
        /*
           for a empty ring, version is the mapping head val - size
           so the empty ring's ver is loop-size;
         */
        ring->ring[loop].data_s.ver = (loop - ring->size);
        ring->ring[loop].data_s.val = 0;
    }

    return;
}

/*****************************************************************************
*   Prototype    : nsfw_mem_ring_free_count
*   Description  : get the free number of ring
*   Input        : mring_handle mhandle
*   Output       : None
*   Return Value : u32
*   Calls        :
*   Called By    :
*****************************************************************************/
u32 nsfw_mem_ring_free_count(mring_handle mhandle)
{
    struct nsfw_mem_ring *temp = NULL;
    u32 thead = 0;
    u32 ttail = 0;
    u32 using_count = 0;
    if (NULL == mhandle)
    {
        NSRTP_LOGERR("input para error] mhandle=%p", mhandle);
        return 0;
    }

    temp = (struct nsfw_mem_ring *) mhandle;

    /* avoid multi-thread issue, here we should get cons.tail firstly, get prod.head later
       because tail and head is always ++ */
    /* optimize nsfw_mem_ring_using_count(), avoid return abnormal value */
    ttail = temp->cons.tail;
    thead = temp->prod.head;

    using_count = thead - ttail;
    if (using_count > temp->size)
    {
        /* nsfw_mem_ring_using_count will return abnormal lagre value */
        using_count = 0;
    }

    return temp->size - (using_count);
}

/*****************************************************************************
*   Prototype    : nsfw_mem_ring_using_count
*   Description  : get the in using number of ring
*   Input        : mring_handle mhandle
*   Output       : None
*   Return Value : u32
*   Calls        :
*   Called By    :
*****************************************************************************/
u32 nsfw_mem_ring_using_count(mring_handle mhandle)
{
    struct nsfw_mem_ring *temp = NULL;
    u32 thead = 0;
    u32 ttail = 0;
    u32 using_count = 0;
    if (NULL == mhandle)
    {
        NSRTP_LOGERR("input para error] mhandle=%p", mhandle);
        return 0;
    }

    temp = (struct nsfw_mem_ring *) mhandle;
    /* avoid multi-thread issue, here we should get cons.tail firstly, get prod.head later
       because tail and head is always ++ */
    /* optimize nsfw_mem_ring_using_count(), avoid return abnormal value */

    ttail = temp->cons.tail;
    thead = temp->prod.head;

    using_count = thead - ttail;
    if (using_count > temp->size)
    {
        /* nsfw_mem_ring_using_count will return abnormal lagre value */
        using_count = 0;
    }

    return using_count;
}

u32 nsfw_mem_ring_size(mring_handle mhandle)
{
    struct nsfw_mem_ring *temp = NULL;

    if (NULL == mhandle)
    {
        NSRTP_LOGERR("input para error] mhandle=%p", mhandle);
        return 0;
    }

    temp = (struct nsfw_mem_ring *) mhandle;

    return temp->size;
}

i32 nsfw_mem_ring_release(nsfw_mem_name * pname)
{
    NSFW_MEM_NAME_CHECK_RET_ERR(pname, "ring release");

#ifndef FOR_ATTACH_COREID
    if (nsfw_attach_core_id(pname) != 0)
    {
        return NSFW_MEM_ERR;
    }
#endif

    MEM_OP_CALL_OK_RET(pname->entype, mem_ops_ring_release, (pname));
    NSRTP_LOGERR("ring release fail] name=%s, type=%d", pname->aname,
                 pname->entype);
    return NSFW_MEM_ERR;

}

/*****************************************************************************
*   Prototype    : nsfw_mem_get_len
*   Description  : statics mbufpool, sppool, ring mem size.
*                  return: <=0, err happen, >0 mem size
*                  NSFW_MEM_MZONE: not surport because you already know the lenth when create
*   Input        : void * handle
*                  nsfw_mem_struct_type type
*   Output       : None
*   Return Value : ssize_t
*   Calls        :
*   Called By    :
*****************************************************************************/
ssize_t nsfw_mem_get_len(void *handle, nsfw_mem_struct_type type)
{
    if (NULL == handle)
    {
        NSRTP_LOGERR("input para error] handle=%p", handle);
        return -1;
    }
    if ((NSFW_MEM_SPOOL == type) || (NSFW_MEM_RING == type))
    {
        struct nsfw_mem_ring *ring = (struct nsfw_mem_ring *) handle;
        if (ring->memtype >= NSFW_MEM_TYPEMAX)
        {
            NSRTP_LOGERR("invalid ring] ring type=%u ,handle=%p",
                         ring->memtype, handle);
            return -1;
        }
        MEM_OP_CALL_OK_RET(ring->memtype, mem_ops_mem_statics,
                           (handle, type));
    }
    else
    {
        MEM_OP_CALL_OK_RET(NSFW_SHMEM, mem_ops_mem_statics, (handle, type));
    }
    return -1;
}

/*****************************************************************************
*   Prototype    : nsfw_mem_sp_iterator
*   Description  : spool iterator
*   Input        : mpool_handle handle
*                  u32 start
*                  u32 end
*                  nsfw_mem_item_fun fun
*                  void *argv
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 nsfw_mem_sp_iterator(mpool_handle handle, u32 start, u32 end,
                         nsfw_mem_item_fun fun, void *argv)
{
    MEM_OP_CALL_OK_RET(NSFW_SHMEM, mem_ops_sp_iterator,
                       (handle, start, end, fun, argv));
    return -1;
}

i32 nsfw_mem_mbuf_iterator(mpool_handle handle, u32 start, u32 end,
                           nsfw_mem_item_fun fun, void *argv)
{
    MEM_OP_CALL_OK_RET(NSFW_SHMEM, mem_ops_mbuf_iterator,
                       (handle, start, end, fun, argv));
    return -1;
}

i32 nsfw_mem_ring_iterator(mpool_handle handle, nsfw_mem_item_fun fun,
                           void *argv)
{
    MEM_OP_CALL_OK_RET(NSFW_SHMEM, mem_ops_ring_iterator,
                       (handle, fun, argv));
    return -1;
}

/*****************************************************************************
*   Prototype    : nsfw_mem_get_health_info
*   Description  : get overflow flag and other info
*   Input        : mring_handle mhandle
*   Output       : None
*   Return Value :
*   Calls        :
*   Called By    :
*****************************************************************************/
nsfw_mem_ring_health_info nsfw_mem_get_health_info(mring_handle mhandle)
{
    struct nsfw_mem_ring *temp = (struct nsfw_mem_ring *) mhandle;
    nsfw_mem_ring_health_info ring_health_info;

    ring_health_info.overflow_count = 0;
    ring_health_info.overflow_time.tv_sec = 0;
    ring_health_info.overflow_time.tv_usec = 0;

    ring_health_info.prod.head = 0;
    ring_health_info.prod.tail = 0;

    ring_health_info.cons.head = 0;
    ring_health_info.cons.tail = 0;

    ring_health_info.size = 0;
    ring_health_info.mask = 0;

    if (NULL == temp)
    {
        NSRTP_LOGERR("invalid parameter]");
        return ring_health_info;
    }
    ring_health_info.overflow_count = temp->overflow_count;
    ring_health_info.overflow_time = temp->overflow_time;
    ring_health_info.prod.head = temp->prod.head;
    ring_health_info.prod.tail = temp->prod.tail;

    ring_health_info.cons.head = temp->cons.head;
    ring_health_info.cons.tail = temp->cons.tail;

    ring_health_info.size = temp->size;
    ring_health_info.mask = temp->mask;

    return ring_health_info;
}

/* *INDENT-OFF* */
NSFW_MODULE_NAME(NSFW_MEM_MGR_MODULE)
NSFW_MODULE_PRIORITY(10)
NSFW_MODULE_INIT(nsfw_mem_init)
/* *INDENT-ON* */
