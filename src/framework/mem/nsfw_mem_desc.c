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
#include "nsfw_mem_api.h"
#include "dmm_shmem_mng.h"
#include "dmm_nshmem_mng.h"
#include "dmm_ring.h"

/* *INDENT-OFF* */
/*the inferaces accessing memory*/
static nsfw_mem_ops dmm_shmem_ops =
{
    dmm_shmem_init,
    dmm_shmem_destroy,
    dmm_shmem_create,
    NULL,//nsfw_shmem_createv,
    dmm_shmem_lookup,
    dmm_shmem_release,
    NULL,//dmm_shmem_mbfmpcreate,
    NULL,//dmm_shmem_mbfmpcreatev,
    NULL,//dmm_shmem_mbfmplookup,
    NULL,//dmm_shmem_mbfmprelease,
    NULL,//dmm_shmem_spcreate,
    NULL,//dmm_shmem_spcreatev,
    dmm_shmem_sp_ringcreate,
    dmm_shmem_sprelease,
    dmm_shmem_sp_lookup,
    dmm_shmem_ringcreate,
    dmm_shmem_ring_lookup,
    dmm_shmem_ringrelease,
    dmm_shmem_stactic,
    NULL,//dmm_shmem_sp_iterator,
    NULL,//nsfw_shmem_mbuf_iterator,
    NULL,//nsfw_shmem_ring_iterator,
    dmm_shmem_shddr_to_laddr,
    dmm_shmem_laddr_to_shddr,
    dmm_attach_core_id
};

/*no share memory access inferface*/
static nsfw_mem_ops dmm_nshmem_ops =
{
    dmm_nshmem_init,
    dmm_nshmem_destory,
    dmm_nshmem_create,
    NULL,
    NULL,//nsfw_nshmem_lookup,
    NULL,//nsfw_nshmem_release,
    NULL,
    NULL,
    NULL,
    NULL,
    dmm_nshmem_spcreate,
    NULL,
    NULL,
    dmm_nshmem_sprelease,
    NULL,//nsfw_nshmem_sp_lookup,
    dmm_nshmem_ringcreate,
    NULL,
    dmm_nshmem_ringrelease,
    dmm_nshmem_stactic,
    //NULL,
    NULL,/*mem_ops_sp_iterator*/
    NULL,/*mem_ops_mbuf_iterator*/
};

/*the order you add must be NSFW_SHMEM, NSFW_NSHMEM*/
nsfw_mem_attr g_nsfw_mem_ops[] =
{
    {NSFW_SHMEM, &dmm_shmem_ops},
    {NSFW_NSHMEM, &dmm_nshmem_ops}
};
/* *INDENT-ON* */

i32 g_mem_type_num = sizeof(g_nsfw_mem_ops) / sizeof(nsfw_mem_attr);

nsfw_ring_ops g_ring_ops_arry[NSFW_MEM_TYPEMAX][NSFW_MPOOL_TYPEMAX] = {
    {
     [NSFW_MRING_MPMC] = {
                          .ring_ops_enqueue = dmm_mem_enqueue,
                          .ring_ops_dequeue = dmm_mem_dequeue}
     }
    ,
    {
     [NSFW_MRING_MPMC] = {
                          .ring_ops_enqueue = dmm_mem_enqueue,
                          .ring_ops_dequeue = dmm_mem_dequeue}
     }
};
