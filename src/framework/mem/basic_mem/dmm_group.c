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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "nsfw_base_linux_api.h"
#include "nstack_log.h"
#include "dmm_config.h"
#include "dmm_group.h"
#include "dmm_pause.h"
#include "nstack_securec.h"

#define DMM_GROUP_ACTIVE 0x55D5551
#define DMM_GROUP_GLOBAL "global"
#define DMM_GROUP_ENV "DMM_GROUP"
#define DMM_GROUP_FMT "%s/dmm-group-%s" /* VAR_DIR group-name */

static struct flock group_lock = {
    .l_type = F_WRLCK,
    .l_whence = SEEK_SET,
    .l_start = 0,
    .l_len = sizeof(struct dmm_group),
};

static int group_fd = -1;
struct dmm_group *main_group = NULL;

inline static const char *get_group_path()
{
    static char group_path[PATH_MAX] = "";

    if (!group_path[0])
    {
        const char *group = getenv(DMM_GROUP_ENV);

        if (!group || !group[0])
            group = DMM_GROUP_GLOBAL;

        (void) snprintf_s(group_path, sizeof(group_path),
                          sizeof(group_path) - 1, DMM_GROUP_FMT,
                          DMM_VAR_DIR, group);
        group_path[sizeof(group_path) - 1] = 0;
    }

    return group_path;
}

void dmm_group_active()
{
    main_group->group_init = DMM_GROUP_ACTIVE;
    NSFW_LOGINF("main group actived");
}

int dmm_group_create_main()
{
    int ret;
    const char *path = get_group_path();

    NSFW_LOGINF("start create main group '%s'", path);

    group_fd = open(path, O_RDWR | O_CREAT, 0600);
    if (group_fd < 0)
    {
        NSFW_LOGERR("open file failed, path:'%s', errno=%d", path, errno);
        return -1;
    }

    ret = ftruncate(group_fd, sizeof(struct dmm_group));
    if (ret < 0)
    {
        NSFW_LOGERR("set size failed, path:'%s' size:%lu, errno=%d",
                    path, sizeof(struct dmm_group), errno);
        (void) nsfw_base_close(group_fd);
        group_fd = -1;
        return -1;
    }

    ret = fcntl(group_fd, F_SETLK, &group_lock);
    if (ret < 0)
    {
        NSFW_LOGERR("lock file failed, path:'%s', errno=%d", path, errno);
        (void) nsfw_base_close(group_fd);
        group_fd = -1;
        return -1;
    }

    main_group = (struct dmm_group *) mmap(NULL, sizeof(struct dmm_group),
                                           PROT_READ | PROT_WRITE,
                                           MAP_SHARED, group_fd, 0);

    if (main_group == MAP_FAILED)
    {
        NSFW_LOGERR("mmap failed, path:'%s' size:%lu, errno:%d",
                    path, sizeof(struct dmm_group), errno);
        (void) nsfw_base_close(group_fd);
        group_fd = -1;
        return -1;
    }

    NSFW_LOGINF("main group created, main_group:%p size:%lu",
                main_group, sizeof(struct dmm_group));

    return 0;
}

int dmm_group_delete_main()
{
    if (main_group)
    {
        (void) munmap(main_group, sizeof(struct dmm_group));
        main_group = NULL;
    }

    if (group_fd >= 0)
    {
        (void) nsfw_base_close(group_fd);
        group_fd = -1;
    }

    (void) unlink(get_group_path());

    return 0;
}

int dmm_group_attach_main()
{
    const char *path = get_group_path();

    NSFW_LOGINF("Start attach main group '%s'", path);

    group_fd = open(path, O_RDONLY);
    if (group_fd < 0)
    {
        //NSFW_LOGERR ("open group file failed, path:'%s', errno=%d",
        //path, errno);
        return -1;
    }

    main_group = (struct dmm_group *) mmap(NULL, sizeof(struct dmm_group),
                                           PROT_READ, MAP_SHARED, group_fd,
                                           0);
    if (main_group == MAP_FAILED)
    {
        NSFW_LOGERR("mmap failed, path:'%s', errno=%d", path, errno);
        (void) nsfw_base_close(group_fd);
        group_fd = -1;
        return -1;
    }

    while (main_group->group_init != DMM_GROUP_ACTIVE)
    {
        dmm_pause();
    }

    if (kill(main_group->share.pid, 0))
    {
        NSFW_LOGERR
            ("main group process not exist, path:'%s' pid:%d errno=%d", path,
             main_group->share.pid, errno);
        (void) munmap(main_group->share.base, main_group->share.size);
        (void) nsfw_base_close(group_fd);
        (void) unlink(path);
        group_fd = -1;
        return -1;
    }

    NSFW_LOGINF("main group attached, main_group=%p"
                " {type=%d pid=%d base=%p size=%zd path='%s'}",
                main_group, main_group->share.type, main_group->share.pid,
                main_group->share.base, main_group->share.size,
                main_group->share.path);

    return 0;
}

int dmm_group_detach_main()
{
    if (main_group)
    {
        (void) munmap(main_group, sizeof(struct dmm_group));
        main_group = NULL;
    }

    if (group_fd >= 0)
    {
        (void) nsfw_base_close(group_fd);
        group_fd = -1;
    }

    return 0;
}
