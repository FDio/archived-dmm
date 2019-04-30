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

#ifndef _DMM_NSHMEM_MNG_H
#define _DMM_NSHMEM_MNG_H

#include "nsfw_mem_api.h"
#include "types.h"
#include <unistd.h>

i32 dmm_nshmem_init(nsfw_mem_para * para);
void dmm_nshmem_destory(void);
mzone_handle dmm_nshmem_create(nsfw_mem_zone * pinfo);
mring_handle dmm_nshmem_spcreate(nsfw_mem_sppool * pmpinfo);
i32 dmm_nshmem_sprelease(nsfw_mem_name * pname);
mring_handle dmm_nshmem_ringcreate(nsfw_mem_mring * pringinfo);
i32 dmm_nshmem_ringrelease(nsfw_mem_name * pname);
ssize_t dmm_nshmem_sppool_statics(mring_handle sppool);
ssize_t dmm_nshmem_ring_statics(mring_handle handle);
ssize_t dmm_nshmem_stactic(void *handle, nsfw_mem_struct_type type);

#endif
