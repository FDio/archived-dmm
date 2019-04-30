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

/*==============================================*
 *      include header files                    *
 *----------------------------------------------*/
#include "select_adapt.h"

/*==============================================*
 *      constants or macros define              *
 *----------------------------------------------*/

/*==============================================*
 *      project-wide global variables           *
 *----------------------------------------------*/
struct select_fd_map_inf g_select_fd_map;

/*==============================================*
 *      routines' or functions' implementations *
 *----------------------------------------------*/

void *select_alloc(int size)
{

    char *p;
    if (size <= 0)
    {
        return NULL;
    }

    p = malloc(size);
    if (!p)
    {
        return NULL;
    }
    if (EOK != memset_s(p, size, 0, size))
    {
        free(p);
        p = NULL;
    }

    return p;
}

/*point is set to NULL because it's freeed */
void select_free(void *p)
{

    if (p)
    {
        free(p);
        p = NULL;
    }
}

struct select_comm_fd_map *get_select_fdinf(i32 fd)
{
    if ((fd < 0) || ((u32) fd >= NSTACK_SELECT_MAX_FD))
    {
        return NULL;
    }
    return (&g_select_fd_map.fdinf[fd]);
}

void reset_select_fdinf(i32 fd)
{
    i32 i;
    struct select_comm_fd_map *fdinf = get_select_fdinf(fd);
    /* fdinf is possible is null */
    if (NULL == fdinf)
    {
        return;
    }
    fdinf->index = -1;
    for (i = 0; i < NSTACK_MAX_MODULE_NUM; i++)
    {
        fdinf->mod_fd[i] = -1;
    }
}

i32 select_get_modfd(i32 fd, i32 inx)
{
    if ((fd < 0) || ((u32) fd >= NSTACK_SELECT_MAX_FD))
    {
        return -1;
    }
    if ((inx < 0))
    {
        return -1;
    }
    if (!g_select_fd_map.fdinf)
    {
        return FALSE;
    }
    return (g_select_fd_map.fdinf[fd].mod_fd[inx]);

}

i32 select_set_modfd(i32 fd, i32 inx, i32 modfd)
{
    if ((fd < 0) || ((u32) fd >= NSTACK_SELECT_MAX_FD))
    {
        return -1;
    }
    if (!g_select_fd_map.fdinf)
    {
        return FALSE;
    }
    g_select_fd_map.fdinf[fd].mod_fd[inx] = modfd;

    return TRUE;
}

i32 select_get_modindex(i32 fd)
{
    if ((fd < 0) || ((u32) fd >= NSTACK_SELECT_MAX_FD))
    {
        return -1;
    }
    return g_select_fd_map.fdinf[fd].index;
}

i32 select_get_commfd(i32 modfd, i32 inx)
{

    if ((modfd < 0) || ((u32) modfd >= NSTACK_SELECT_MAX_FD))
    {
        return -1;
    }
    return g_select_fd_map.modinf[inx].comm_fd[modfd];
}

i32 select_set_commfd(i32 modfd, i32 inx, i32 fd)
{
    if ((modfd < 0) || ((u32) modfd >= NSTACK_SELECT_MAX_FD))
    {
        return -1;
    }
    if (!g_select_fd_map.modinf[inx].comm_fd)
    {
        return FALSE;
    }
    g_select_fd_map.modinf[inx].comm_fd[modfd] = fd;

    return TRUE;
}

i32 select_set_index(i32 fd, i32 inx)
{
    if ((fd < 0) || ((u32) fd >= NSTACK_SELECT_MAX_FD))
    {
        return -1;
    }
    if (!g_select_fd_map.fdinf)
    {
        return FALSE;
    }
    g_select_fd_map.fdinf[fd].index = inx;
    return TRUE;
}

i32 fdmapping_init(void)
{
    int ret = FALSE;
    int i, inx;

    g_select_fd_map.fdinf =
        (struct select_comm_fd_map *)
        select_alloc(sizeof(struct select_comm_fd_map) *
                     NSTACK_SELECT_MAX_FD);
    if (NULL == g_select_fd_map.fdinf)
    {
        goto err_return;
    }

    for (i = 0; i < nstack_get_module_num(); i++)
    {
        g_select_fd_map.modinf[i].comm_fd =
            (i32 *) select_alloc(sizeof(i32) * NSTACK_SELECT_MAX_FD);
        if (NULL == g_select_fd_map.modinf[i].comm_fd)
        {
            goto err_return;
        }
    }

    u32 fd_idx = 0;
    for (fd_idx = 0; fd_idx < NSTACK_SELECT_MAX_FD; fd_idx++)
    {
        reset_select_fdinf(fd_idx);
    }

    for (inx = 0; inx < nstack_get_module_num(); inx++)
    {
        for (fd_idx = 0; fd_idx < NSTACK_SELECT_MAX_FD; fd_idx++)
        {
            select_set_commfd(fd_idx, inx, -1);
        }
    }

    ret = TRUE;
    return ret;
  err_return:

    select_free((char *) g_select_fd_map.fdinf);
    for (i = 0; i < nstack_get_module_num(); i++)
    {
        select_free((char *) g_select_fd_map.modinf[i].comm_fd);
    }

    return ret;
}
