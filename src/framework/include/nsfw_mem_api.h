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

#ifndef _NSFW_MEM_API_H
#define _NSFW_MEM_API_H
#include <stdint.h>
#include <sys/types.h>

#include "types.h"
#include "nsfw_mgr_com_api.h"
#include "nstack_log.h"
#include <unistd.h>
#include <string.h>

#define NSFW_MEM_MGR_MODULE "nsfw_mem_mgr"

/*
 *the max len of memory name is 32bytes, but app just can use max 22bytes, left 10bytes to memory manager module
 */
#define NSFW_MEM_NAME_LENTH     (32)
#define NSFW_MEM_APPNAME_LENTH  (22)

#define NSFW_SOCKET_ANY     (-1)

#define NSFW_MEM_NOT_INIT  (0)
#define NSFW_MEM_INIT_ERR  (1)
#define NSFW_MEM_INIT_OK   (2)

/*
 * type of init error
 */
typedef enum
{
    NSFW_MEM_ERR_MISALIGN = -2,
    NSFW_MEM_ERR = -1,
    NSFW_MEM_OK = 0,
    NSFW_MEM_RTP_FAIL = 1,      /* init rtp fail */
    NSFW_MEM_MALLOC_FAIL = 2,   /* mem alloc fail */
    NSFW_MEM_MEMSET_FAIL = 3,
} nsfw_init_errno;

/*
 *type of memory:
 *NSFW_SHMEM:shared memory
 *NSFW_NSHMEM:allocated by calling malloc
 */
typedef enum
{
    NSFW_SHMEM,
    NSFW_NSHMEM,
    NSFW_MEM_TYPEMAX,
} nsfw_mem_type;

/*type of ring operation*/
typedef enum
{
    NSFW_MRING_SPSC,            /*sigle producer sigle consumer ring */
    NSFW_MRING_MPSC,            /*multi producer sigle consumer ring */
    NSFW_MRING_SPMC,            /*sigle producer multi consumer ring */
    NSFW_MRING_MPMC,            /*multi producer multi consumer ring */
    NSFW_MRING_SPSC_ST,         /*single producer single consumer and belong to one thread ring */
    NSFW_MPOOL_TYPEMAX,
} nsfw_mpool_type;

typedef void *mpool_handle;
typedef void *mzone_handle;
typedef void *mbuf_handle;
typedef void *mring_handle;

/*initial of param*/
typedef struct
{
    i32 iargsnum;
    i8 **pargs;
    fw_poc_type enflag;         /*app, daemon-stack, Master */
} nsfw_mem_para;

typedef struct
{
    nsfw_mem_type entype;
    fw_poc_type enowner;        /*notes: 1. when calling any shared memory create inferface, the name of memory end with _0 created by daemon-stack,
                                 *              end with null created by nStackMaster, and end with _<pid> created by other.
                                 *           2. pname->enowner is available only when call look up shared memory.
                                 *           3. if the roles of process is NSFW_PROC_MASTER but the memory was created by others, or pname->enowner is NSFW_PROC_NULL,
                                 *              the name must be full name.
                                 *              for examles if the memory was created by daemon-stack and pname->enowner is NSFW_PROC_NULL,
                                 *              must add '_0' at the end of name, if the memory was created by app and the role of process is NSFW_PROC_MASTER, must add
                                 *              _(pid) at the end of name, nstack_123.
                                 */
    i8 aname[NSFW_MEM_NAME_LENTH];      /*the lenth of name must be less than NSFW_MEM_APPNAME_LENTH. */
} nsfw_mem_name;

typedef struct
{
    nsfw_mem_name stname;
    size_t lenth;
    i32 isocket_id;
    i32 ireserv;
} nsfw_mem_zone;

typedef struct
{
    nsfw_mem_name stname;
    unsigned usnum;             /*the really created mbfpool num is (num+1) power of 2 */
    unsigned uscash_size;
    unsigned uspriv_size;
    unsigned usdata_room;
    i32 isocket_id;
    nsfw_mpool_type enmptype;
} nsfw_mem_mbfpool;

typedef struct
{
    nsfw_mem_name stname;
    u32 usnum;                  /*the really created sppool num is (num+1) power of 2 */
    u32 useltsize;
    i32 isocket_id;
    nsfw_mpool_type enmptype;
} nsfw_mem_sppool;

typedef struct
{
    nsfw_mem_name stname;
    u32 usnum;                  /*the really created ring num is (num+1) power of 2 */
    i32 isocket_id;
    nsfw_mpool_type enmptype;
} nsfw_mem_mring;

typedef enum
{
    NSFW_MEM_ALLOC_SUCC = 1,
    NSFW_MEM_ALLOC_FAIL = 2,
} nsfw_mem_alloc_state;

typedef enum
{
    NSFW_MEM_MZONE,
    NSFW_MEM_MBUF,
    NSFW_MEM_SPOOL,
    NSFW_MEM_RING
} nsfw_mem_struct_type;

typedef enum
{
    NSFW_RESERV_REQ_MSG,
    NSFW_RESERV_ACK_MSG,
    NSFW_MBUF_REQ_MSG,
    NSFW_MBUF_ACK_MSG,
    NSFW_SPPOOL_REQ_MSG,
    NSFW_SPPOOL_ACK_MSG,
    NSFW_RING_REQ_MSG,
    NSFW_RING_ACK_MSG,
    NSFW_RELEASE_REQ_MSG,
    NSFW_RELEASE_ACK_MSG,
    NSFW_MEM_LOOKUP_REQ_MSG,
    NSFW_MEM_LOOKUP_ACK_MSG,
    NSFW_MEM_MAX_MSG
} nsfw_remote_msg;

typedef struct __nsfw_shmem_msg_head
{
    unsigned usmsg_type;
    unsigned uslenth;

    i32 aidata[0];

} nsfw_shmem_msg_head;

typedef struct __nsfw_shmem_ack
{
    void *pbase_addr;
    u16 usseq;
    i8 cstate;
    i8 creserv;
    i32 ireserv;
} nsfw_shmem_ack;

typedef struct __nsfw_shmem_reserv_req
{
    i8 aname[NSFW_MEM_NAME_LENTH];
    u16 usseq;
    u16 usreserv;
    i32 isocket_id;
    size_t lenth;
    i32 ireserv;
} nsfw_shmem_reserv_req;

typedef struct __nsfw_shmem_mbuf_req
{
    i8 aname[NSFW_MEM_NAME_LENTH];
    u16 usseq;
    u16 enmptype;
    unsigned usnum;
    unsigned uscash_size;
    unsigned uspriv_size;
    unsigned usdata_room;
    i32 isocket_id;
    i32 ireserv;
} nsfw_shmem_mbuf_req;

typedef struct __nsfw_shmem_sppool_req
{
    i8 aname[NSFW_MEM_NAME_LENTH];
    u16 usseq;
    u16 enmptype;
    u32 usnum;
    u32 useltsize;
    i32 isocket_id;
    i32 ireserv;
} nsfw_shmem_sppool_req;

typedef struct __nsfw_shmem_ring_req
{
    i8 aname[NSFW_MEM_NAME_LENTH];
    u16 usseq;
    u16 enmptype;
    u32 usnum;
    i32 isocket_id;
    i32 ireserv;
} nsfw_shmem_ring_req;

typedef struct __nsfw_shmem_free_req
{
    i8 aname[NSFW_MEM_NAME_LENTH];
    u16 usseq;
    u16 ustype;                 /*structure of memory(memzone,mbuf,mpool,ring) */
    i32 ireserv;
} nsfw_shmem_free_req;

typedef struct __nsfw_shmem_lookup_req
{
    i8 aname[NSFW_MEM_NAME_LENTH];
    u16 usseq;
    u16 ustype;                 /*structure of memory(memzone,mbuf,mpool,ring) */
    i32 ireserv;
} nsfw_shmem_lookup_req;

typedef struct __nsfw_mem_ring_health_info
{
    struct
    {
        u32 head;               //Head of the Ring, used to indicate pos where to pull a val
        u32 tail;               //for nshmem, shmem not used.
    } prod;
    struct
    {
        u32 head;               //for nshmem, shmem not used.
        u32 tail;               //Tail of the Ring, used to indicate pos where to push a val
    } cons;
    struct timeval overflow_time;
    u32 size;
    u32 mask;
    u16 overflow_count;

} nsfw_mem_ring_health_info;

typedef int (*nsfw_mem_ring_enqueue_fun) (mring_handle ring, void *box);
typedef int (*nsfw_mem_ring_dequeue_fun) (mring_handle ring, void **box);
typedef int (*nsfw_mem_ring_dequeuev_fun) (mring_handle ring, void **box,
                                           unsigned int n);

typedef struct
{
    nsfw_mem_ring_enqueue_fun ring_ops_enqueue;
    nsfw_mem_ring_dequeue_fun ring_ops_dequeue;
    nsfw_mem_ring_dequeuev_fun ring_ops_dequeuev;
} nsfw_ring_ops;

/*
 * memory module init
 * para:point to nstak_fwmem_para
 */
i32 nsfw_mem_init(void *para);

/*
 * create a block memory with name
 * nsfw_mem_zone::stname
 * nsfw_mem_zone::isize
 * note: 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
 */
mzone_handle nsfw_mem_zone_create(nsfw_mem_zone * pinfo);

/*
 *create some memory blocks
 * note: 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
 */
i32 nsfw_mem_zone_createv(nsfw_mem_zone * pmeminfo, i32 inum,
                          mzone_handle * paddr_array, i32 iarray_num);

/*
 *look up a memory
 * note: 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
 *       2. if the memory is shared, pname->enowner indicate that who create this memory,
 *           note:
 *           1. when calling any shared memory create inferface, the name of memory end with _0 created by daemon-stack,
 *              end with none created by nStackMaster, and end with _<pid> created by other.
 *           2. pname->enowner is available only when call look up shared memory.
 *           3. if the roles of process is NSFW_PROC_MASTER but the memory was created by others, or pname->enowner is NSFW_PROC_NULL,
 *              the name must be full name.
 *              for examles if the memory was created by daemon-stack and pname->enowner is NSFW_PROC_NULL,
 *              must add '_0' at the end of name, if the memory was created by app and the role of process is NSFW_PROC_MASTER, must add
 *              _(pid) at the end of name, nstack_123.
 */
mzone_handle nsfw_mem_zone_lookup(nsfw_mem_name * pname);

/*release a memory*/
i32 nsfw_mem_zone_release(nsfw_mem_name * pname);

/*
 *create a mbuf pool
 */
mpool_handle nsfw_mem_mbfmp_create(nsfw_mem_mbfpool * pbufinfo);

/*
 *create some mbuf pools
 * note: 1. the name of lenth must be less than NSFW_MEM_APPNAME_LENTH.
 */
i32 nsfw_mem_mbfmp_createv(nsfw_mem_mbfpool * pmbfname, i32 inum,
                           mpool_handle * phandle_array, i32 iarray_num);

/*
 *look up mbuf mpool
 * note: 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
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
 */
mpool_handle nsfw_mem_mbfmp_lookup(nsfw_mem_name * pmbfname);

/*
 *release mbuf pool
 * note: 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
 */
i32 nsfw_mem_mbfmp_release(nsfw_mem_name * pname);

/*
 *create a simple pool
 *note: 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
 */
mring_handle nsfw_mem_sp_create(nsfw_mem_sppool * pmpinfo);

/*
 *create some simple pools one time
 *note: 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
 */
i32 nsfw_mem_sp_createv(nsfw_mem_sppool * pmpinfo, i32 inum,
                        mring_handle * pringhandle_array, i32 iarray_num);

/*
 *create a simple pool with many rings
 *note: 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
 */
i32 nsfw_mem_sp_ring_create(nsfw_mem_mring * prpoolinfo,
                            mring_handle * pringhandle_array, i32 iringnum);

/*
 *release a simple mempool
 *note: 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
 */
i32 nsfw_mem_sp_release(nsfw_mem_name * pname);

/*
 *look up a simpile ring
 * note: 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
 *       2. if the memory is shared, pname->enowner indicate that who create this memory,
 *           note:
 *           1. when calling any shared memory create inferface, the name of memory end with _0 created by daemon-stack,
 *              end with none created by nStackMaster, and end with _<pid> created by other.
 *           2. pname->enowner is available only when call look up shared memory.
 *           3. if the roles of process is NSFW_PROC_MASTER but the memory was created by others, or pname->enowner is NSFW_PROC_NULL,
 *              the name must be full name.
 *              for examles if the memory was created by daemon-stack and pname->enowner is NSFW_PROC_NULL,
 *              must add '_0' at the end of name, if the memory was created by app and the role of process is NSFW_PROC_MASTER, must add
 *              _(pid) at the end of name, nstack_123.
 */
mring_handle nsfw_mem_sp_lookup(nsfw_mem_name * pname);

/*
 *create a ring
 *note: 1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
 *      2. shared memory ring (NSFW_SHMEM) just can put a pointor into the queue, the queue also point to a shared block memory.
 *         no shared memory ring(NSFW_NSHMEM) is other wise.
 */
mring_handle nsfw_mem_ring_create(nsfw_mem_mring * pringinfo);

/*
 *look up a ring by name
 * note:1. the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
 *       2. if the memory is shared, pname->enowner indicate that who create this memory,
 *           note:
 *           1. when calling any shared memory create inferface, the name of memory end with _0 created by daemon-stack,
 *              end with none created by nStackMaster, and end with _<pid> created by other.
 *           2. pname->enowner is available only when call look up shared memory.
 *           3. if the roles of process is NSFW_PROC_MASTER but the memory was created by others, or pname->enowner is NSFW_PROC_NULL,
 *              the name must be full name.
 *              for examles if the memory was created by daemon-stack and pname->enowner is NSFW_PROC_NULL,
 *              must add '_0' at the end of name, if the memory was created by app and the role of process is NSFW_PROC_MASTER, must add
 *              _(pid) at the end of name, nstack_123.
 */
mring_handle nsfw_mem_ring_lookup(nsfw_mem_name * pname);

/*
 * reset the number of producer and consumer, also, the state of ring reset to empty
 * notes: must be called before doing any operations base on the ring
 */
void nsfw_mem_ring_reset(mring_handle mhandle, nsfw_mpool_type entype);

extern nsfw_ring_ops g_ring_ops_arry[NSFW_MEM_TYPEMAX][NSFW_MPOOL_TYPEMAX];

/*****************************************************************************
*   Prototype    : nsfw_mem_ring_dequeue
*   Description  : get a member from a ring
*   note         : if NSFW_SHMEM ring, pdata returned alread a local address
*   Input        : mring_handle mhandle
*                  void** pdata
*   Output       : None
*   Return Value : the num of elment get from the queue, =0: get null, <0: err happen, >0: return num.
*   Calls        :
*   Called By    :
*****************************************************************************/
static inline i32 nsfw_mem_ring_dequeue(mring_handle mhandle, void **pdata)
{
    if (NULL == mhandle || *((u8 *) mhandle) >= NSFW_MEM_TYPEMAX
        || *((u8 *) mhandle + 1) >= NSFW_MPOOL_TYPEMAX)
    {
        NSRTP_LOGERR("input para error] mhandle=%p", mhandle);
        return -1;
    }

    return
        g_ring_ops_arry[*((u8 *) mhandle)][*
                                           ((u8 *) mhandle +
                                            1)].ring_ops_dequeue(mhandle,
                                                                 pdata);
}

/*****************************************************************************
*   Prototype    : nsfw_mem_ring_dequeuev
*   Description  : get some members from a ring
*   note         : if NSFW_SHMEM ring, pdata returned alread a local address
*   Input        : mring_handle mhandle
*                  void** pdata
*                  unsigned inum
*   Output       : None
*   Return Value : the num of elment get from the queue, =0: get null, <0: err happen, >0: return num.
*   Calls        :
*   Called By    :
*****************************************************************************/
static inline i32 nsfw_mem_ring_dequeuev(mring_handle mhandle, void **pdata,
                                         unsigned int inum)
{
    if (NULL == mhandle || *((u8 *) mhandle) >= NSFW_MEM_TYPEMAX
        || *((u8 *) mhandle + 1) >= NSFW_MPOOL_TYPEMAX)
    {
        NSRTP_LOGERR("input para error] mhandle=%p", mhandle);
        return -1;
    }

    return
        g_ring_ops_arry[*((u8 *) mhandle)][*
                                           ((u8 *) mhandle +
                                            1)].ring_ops_dequeuev(mhandle,
                                                                  pdata,
                                                                  inum);
}

/*****************************************************************************
*   Prototype    : nsfw_mem_ring_enqueue
*   Description  : put a member back into a ring
*   note         : pdata must point to a shared block memory when put into the NSFW_SHMEM type memory ring, and the
*                  value of pdata must be local address
*   Input        : mring_handle mhandle
*                  void* pdata
*   Output       : None
*   Return Value : the num of elment put into the queue, =0: put null, <0: err happen, >0: return num.
*   Calls        :
*   Called By    :
*****************************************************************************/
static inline i32 nsfw_mem_ring_enqueue(mring_handle mhandle, void *pdata)
{
    if (NULL == mhandle || *((u8 *) mhandle) >= NSFW_MEM_TYPEMAX
        || *((u8 *) mhandle + 1) >= NSFW_MPOOL_TYPEMAX)
    {
        NSRTP_LOGERR("input para error] mhandle=%p", mhandle);
        return -1;
    }

    return
        g_ring_ops_arry[*((u8 *) mhandle)][*
                                           ((u8 *) mhandle +
                                            1)].ring_ops_enqueue(mhandle,
                                                                 pdata);
}

/*
 *get the free number of ring
 */
u32 nsfw_mem_ring_free_count(mring_handle mhandle);

/*
 *get the in using number of ring
 */
u32 nsfw_mem_ring_using_count(mring_handle mhandle);

/*
 *get size of ring
 */
u32 nsfw_mem_ring_size(mring_handle mhandle);

/*
 *release a ring memory
 *note: the lenth of name must be less than NSFW_MEM_APPNAME_LENTH.
 */
i32 nsfw_mem_ring_release(nsfw_mem_name * pname);

/*
 *statics mbufpool, sppool, ring mem size
 *return: <=0, err happen, >0 mem size
 * NSFW_MEM_MZONE: not surport because you already know the lenth when create
 */
ssize_t nsfw_mem_get_len(void *handle, nsfw_mem_struct_type type);

typedef int (*nsfw_mem_item_fun) (void *data, void *argv);

i32 nsfw_mem_sp_iterator(mpool_handle handle, u32 start, u32 end,
                         nsfw_mem_item_fun fun, void *argv);
i32 nsfw_mem_mbuf_iterator(mpool_handle handle, u32 start, u32 end,
                           nsfw_mem_item_fun fun, void *argv);
i32 nsfw_mem_ring_iterator(mpool_handle handle, nsfw_mem_item_fun fun,
                           void *argv);

nsfw_mem_ring_health_info nsfw_mem_get_health_info(mring_handle mhandle);

typedef struct
{
    fw_poc_type enflag;         /*app, daemon-stack, Master */
} nsfw_mem_localdata;

/*memory access inferface define*/
typedef struct
{
    i32(*mem_ops_init) (nsfw_mem_para * para);
    void (*mem_ops_destroy) (void);
      mzone_handle(*mem_ops_zone_creae) (nsfw_mem_zone * pinfo);
      i32(*mem_ops_zone_createv) (nsfw_mem_zone * pmeminfo, i32 inum,
                                  mzone_handle * paddr_array, i32 iarray_num);
      mzone_handle(*mem_ops_zone_lookup) (nsfw_mem_name * pname);
      i32(*mem_ops_mzone_release) (nsfw_mem_name * pname);
      mpool_handle(*mem_ops_mbfmp_create) (nsfw_mem_mbfpool * pbufinfo);
      i32(*mem_ops_mbfmp_createv) (nsfw_mem_mbfpool * pmbfname, i32 inum,
                                   mpool_handle * phandle_array,
                                   i32 iarray_num);
      mpool_handle(*mem_ops_mbfmp_lookup) (nsfw_mem_name * pmbfname);
      i32(*mem_ops_mbfmp_release) (nsfw_mem_name * pname);
      mring_handle(*mem_ops_sp_create) (nsfw_mem_sppool * pmpinfo);
      i32(*mem_ops_sp_createv) (nsfw_mem_sppool * pmpinfo, i32 inum,
                                mring_handle * pringhandle_array,
                                i32 iarray_num);
      i32(*mem_ops_spring_create) (nsfw_mem_mring * prpoolinfo,
                                   mring_handle * pringhandle_array,
                                   i32 iringnum);
      i32(*mem_ops_sp_release) (nsfw_mem_name * pname);
      mring_handle(*mem_ops_sp_lookup) (nsfw_mem_name * pname);
      mring_handle(*mem_ops_ring_create) (nsfw_mem_mring * pringinfo);
      mring_handle(*mem_ops_ring_lookup) (nsfw_mem_name * pname);
      i32(*mem_ops_ring_release) (nsfw_mem_name * pname);
      ssize_t(*mem_ops_mem_statics) (void *handle, nsfw_mem_struct_type type);
      i32(*mem_ops_sp_iterator) (mpool_handle handle, u32 start, u32 end,
                                 nsfw_mem_item_fun fun, void *argv);
      i32(*mem_ops_mbuf_iterator) (mpool_handle handle, u32 start, u32 end,
                                   nsfw_mem_item_fun fun, void *argv);
      i32(*mem_ops_ring_iterator) (mpool_handle handle,
                                   nsfw_mem_item_fun fun, void *argv);
    void *(*mem_ops_shddr_to_laddr) (void *addr);
      uint64_t(*mem_ops_laddr_to_shddr) (void *addr);
    int (*mem_ops_attach_core_id) (nsfw_mem_name * name);
} nsfw_mem_ops;

 /**/ typedef struct
{
    nsfw_mem_type entype;
    nsfw_mem_ops *stmemop;
} nsfw_mem_attr;

extern nsfw_mem_attr g_nsfw_mem_ops[];
extern i32 g_mem_type_num;

#define SHMEM_ADDR_SHTOL(addr)   (g_nsfw_mem_ops[NSFW_SHMEM].stmemop->mem_ops_shddr_to_laddr(addr))
#define SHMEM_ADDR_LTOSH(addr)   (g_nsfw_mem_ops[NSFW_SHMEM].stmemop->mem_ops_laddr_to_shddr(addr))
#define SHMEM_PTR_SHTOL(type, addr)    ((type)SHMEM_ADDR_SHTOL(addr))
#define SHMEM_ADDR_LTOSH_EXT(addr)   (SHMEM_ADDR_LTOSH(addr))
#endif
