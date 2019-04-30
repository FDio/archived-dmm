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
#include <stdlib.h>

#include "types.h"
#include "dmm_config.h"
#include "dmm_memory.h"
#include "dmm_group.h"

#include "nsfw_init_api.h"
#include "nsfw_mgr_com_api.h"
#include "nstack_log.h"
#include "nsfw_mem_api.h"

#define DMM_MEGABYTE (1024 * 1024)

/* shared from main process */
static struct dmm_share *main_share = NULL;
struct dmm_segment *main_seg = NULL;

/* shared by process tree */
static struct dmm_share base_share = { 0 };

struct dmm_segment *base_seg = NULL;

int dmm_mem_main_init()
{
    int ret;

    ret = dmm_group_create_main();
    if (ret)
    {
        return -1;
    }

    main_share = &main_group->share;
    main_share->type = DMM_MAIN_SHARE_TYPE;
    main_share->size = DMM_MAIN_SHARE_SIZE;
    main_share->size *= DMM_MEGABYTE;
    main_share->base = NULL;
    main_share->pid = getpid();
    ret = dmm_share_create(main_share);
    if (ret)
    {
        return -1;
    }

    main_seg = dmm_seg_create(main_share->base, main_share->size);
    if (!main_seg)
    {
        return -1;
    }

    base_seg = main_seg;

    dmm_group_active();

    return 0;
}

int dmm_mem_main_exit()
{
    dmm_group_delete_main();
    return 0;
}

int dmm_mem_app_init()
{
    int ret;

    ret = dmm_group_attach_main();
    if (0 == ret)
    {
        main_share = &main_group->share;
        ret = dmm_share_attach(main_share);
        if (ret)
        {
            NSFW_LOGERR
                ("share attach failed, type:%d pid:%d base:%p size:%lu path:%s",
                 main_share->type, main_share->pid, main_share->base,
                 main_share->size, main_share->path);
            return -1;
        }

        main_seg = dmm_seg_attach(main_share->base, main_share->size);
        if (!main_seg)
        {
            NSFW_LOGERR("segment attach failed, base:%p size:%lu",
                        main_share->base, main_share->size);
            return -1;
        }

        /* now share main process share-memory */
        base_seg = main_seg;
    }
    else
    {
        base_share.type = DMM_SHARE_TYPE;
        base_share.size = 128 * DMM_MEGABYTE;
        base_share.base = NULL;
        base_share.pid = getpid();
        ret = dmm_share_create(&base_share);
        if (ret)
        {
            return -1;
        }

        base_seg = dmm_seg_create(base_share.base, base_share.size);
        if (!base_seg)
        {
            return -1;
        }
    }

    return 0;
}

void dmm_share_destroy()
{
    (void) dmm_share_delete(&base_share);
    return;
}

int dmm_mem_app_exit()
{
    dmm_group_detach_main();

    if (base_share.base)
        dmm_share_delete(&base_share);

    base_share.base = NULL;
    base_seg = NULL;
    main_seg = NULL;

    return 0;
}

struct dmm_ring *dmm_create_ring(int num, int flag,
                                 const char name[DMM_MEM_NAME_SIZE])
{
    struct dmm_ring *ring;
    const size_t bufsize = dmm_ring_bufsize(num);

    dmm_lock_map();

    ring = dmm_map(bufsize, name);

    if (ring)
    {
        if (0 != dmm_ring_init(ring, num, 0, flag, NSFW_SHMEM))
        {
            (void) dmm_unmap(ring);
            ring = NULL;
        }
    }

    dmm_unlock_map();

    return ring;
}

struct dmm_ring *dmm_attach_ring(const char name[DMM_MEM_NAME_SIZE])
{
    return (struct dmm_ring *) dmm_lookup(name);
}

struct dmm_ring *dmm_malloc_ring(int num, int flag)
{
    const size_t size = dmm_ring_bufsize(num);
    if (0 == size)
    {
        return NULL;
    }
    struct dmm_ring *ring = malloc(size);

    if (!ring)
        return NULL;

    if (0 != dmm_ring_init(ring, num, 0, flag, NSFW_NSHMEM))
    {
        free(ring);
        return NULL;
    }

    return ring;
}

struct dmm_ring *dmm_create_pool(size_t elt_size, int num, int flag,
                                 const char name[DMM_MEM_NAME_SIZE])
{
    struct dmm_ring *pool;
    const size_t pool_size = dmm_pool_bufsize(num, elt_size);

    dmm_lock_map();

    pool = dmm_map(pool_size, name);

    if (pool)
    {
        if (0 != dmm_pool_init(pool, elt_size, num, flag, NSFW_SHMEM))
        {
            (void) dmm_unmap(pool);
            pool = NULL;
        }
    }

    dmm_unlock_map();

    return pool;
}

struct dmm_ring *dmm_attach_pool(const char name[DMM_MEM_NAME_SIZE])
{
    return (struct dmm_ring *) dmm_lookup(name);
}

struct dmm_ring *dmm_malloc_pool(size_t elt_size, int num, int flag)
{
    const size_t size = dmm_pool_bufsize(num, elt_size);

    if (0 == size)
    {
        return NULL;
    }
    struct dmm_ring *pool = malloc(size);

    if (!pool)
    {
        return NULL;
    }

    if (0 != dmm_pool_init(pool, elt_size, num, flag, NSFW_NSHMEM))
    {
        free(pool);
        return NULL;
    }

    return pool;
}

int dmm_mem_module_init(void *param)
{
    int ret;
    const u32 proc_type = (u32) ((long) param);

    NSFW_LOGINF("dmm mem module init]type=%u", proc_type);

    switch (proc_type)
    {
        case NSFW_PROC_MAIN:
            ret = dmm_mem_main_init();
            break;
        case NSFW_PROC_NULL:
            ret = 0;
            break;
        default:
            ret = dmm_mem_app_init();
            break;
    }

    return ret;
}

/* *INDENT-OFF* */
//NSFW_MODULE_NAME (DMM_MEMORY_MODULE)
//NSFW_MODULE_PRIORITY (10)
//NSFW_MODULE_INIT (dmm_mem_module_init)
/* *INDENT-ON* */
