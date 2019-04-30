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

#ifndef _DMM_SHMEM_MNG_H
#define _DMM_SHMEM_MNG_H

#include <unistd.h>
#include <stdlib.h>
#include "nsfw_mem_api.h"
#include "types.h"

i32 dmm_shmem_init(nsfw_mem_para * para);
void dmm_shmem_destroy(void);
mzone_handle dmm_shmem_create(nsfw_mem_zone * pinfo);
i32 dmm_shmem_createv(nsfw_mem_zone * pmeminfo, i32 inum,
                      mzone_handle * paddr_array, i32 iarray_num);
mzone_handle dmm_shmem_lookup(nsfw_mem_name * pname);
i32 dmm_shmem_release(nsfw_mem_name * pname);
mpool_handle dmm_shmem_mbfmpcreate(nsfw_mem_mbfpool * pbufinfo);
i32 dmm_shmem_mbfmpcreatev(nsfw_mem_mbfpool * pmbfname, i32 inum,
                           mpool_handle * phandle_array, i32 iarray_num);
mpool_handle dmm_shmem_mbfmplookup(nsfw_mem_name * pmbfname);
i32 dmm_shmem_mbfmprelease(nsfw_mem_name * pname);
i32 dmm_shmem_spcreatev(nsfw_mem_sppool * pmpinfo, i32 inum,
                        mring_handle * pringhandle_array, i32 iarray_num);
i32 dmm_shmem_sp_ringcreate(nsfw_mem_mring * prpoolinfo,
                            mring_handle * pringhandle_array, i32 iringnum);
i32 dmm_shmem_sprelease(nsfw_mem_name * pname);
mring_handle dmm_shmem_sp_lookup(nsfw_mem_name * pname);
mring_handle dmm_shmem_ringcreate(nsfw_mem_mring * pringinfo);
mring_handle dmm_shmem_ring_lookup(nsfw_mem_name * pname);
i32 dmm_shmem_ringrelease(nsfw_mem_name * pname);
size_t dmm_shmem_sppool_statics(mring_handle sppool);
size_t dmm_shmem_ring_statics(mring_handle handle);
ssize_t dmm_shmem_stactic(void *handle, nsfw_mem_struct_type type);
i32 dmm_shmem_sp_iterator(mpool_handle handle, u32 start, u32 end,
                          nsfw_mem_item_fun fun, void *argv);
void *dmm_shmem_shddr_to_laddr(void *addr);
uint64_t dmm_shmem_laddr_to_shddr(void *addr);
int dmm_attach_core_id(nsfw_mem_name * name);
#endif
