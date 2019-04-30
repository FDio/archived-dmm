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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "nstack_module.h"
#include "nstack_log.h"
#include "nstack_select.h"
#include "nstack_securec.h"
#include "nstack_rd.h"
#include "nstack_epoll_api.h"
#include "nstack_info_parse.h"
#include "nsfw_mem_api.h"

/* *INDENT-OFF* */
nstack_module_info g_nstack_modules = {
                                .modNum = 0,
                                .fix_mid = -1,
                                .modules = {{{0}}},
                                .defMod = NULL,
                            };

nstack_module_keys g_nstack_module_desc[NSTACK_MAX_MODULE_NUM];
ns_uint32 g_module_num = 0;
nstack_proc_ops nstack_fd_deal[NSTACK_MAX_MODULE_NUM];
/* *INDENT-ON* */

extern rd_route_table *g_rd_table_handle[NSTACK_MAX_MODULE_NUM];

int nstack_get_deploy_type()
{
    int icnt = 0;
    int type = 0;
    for (icnt = 0; icnt < g_module_num; icnt++)
    {
        if (g_nstack_module_desc[icnt].deploytype > type)
        {
            type = g_nstack_module_desc[icnt].deploytype;
        }
    }
    return type;
}

NSTACK_STATIC inline int
nstack_register_one_module_forchild(nstack_module_keys * pKeys)
{
    nstack_module *pmod = NULL;
    nstack_stack_register_fn stack_register_fn = NULL;
    nstack_event_ops val = { 0 };
    int ret = 0;

    if (pKeys->modInx >= NSTACK_MAX_MODULE_NUM)
    {
        NSSOC_LOGERR
            ("pKeys->modInx is too large]pKeys->modName=%s,pKeys->modInx=%d",
             pKeys->modName, pKeys->modInx);
        return -1;
    }

    pmod = nstack_get_module(pKeys->modInx);
    /*There are some unsafe function ,need to be replace with safe function */
    ret =
        strncpy_s(pmod->modulename, NSTACK_MODULE_NAME_MAX, pKeys->modName,
                  NSTACK_MODULE_NAME_MAX - 1);
    if (EOK != ret)
    {
        NSSOC_LOGERR("strncpy_s failed]ret=%d", ret);
        return -1;
    }
    pmod->modulename[NSTACK_MODULE_NAME_MAX - 1] = '\0';
    pmod->priority = pKeys->priority;
    pmod->modInx = pKeys->modInx;
    pmod->maxfdid = pKeys->maxfdid;
    pmod->minfdid = pKeys->minfdid;

    if (pKeys->libtype == NSTACK_LIB_LOAD_DYN)
    {
        pmod->handle = dlopen(pKeys->libPath, RTLD_LAZY);
        if (!pmod->handle)
        {
            NSSOC_LOGERR
                ("dlopen failed, lib=%s of module=%s, error string=%s",
                 pKeys->libPath, pKeys->modName, dlerror());
            return -1;
        }
    }
    else
    {
        pmod->handle = RTLD_DEFAULT;
    }

    stack_register_fn = dlsym(pmod->handle, pKeys->register_fn_name);
    if (!stack_register_fn)
    {
        /* optimize dlopen err print Begin */
        NSSOC_LOGERR("register function not found]err_string=%s", dlerror());
        /* optimize dlopen err print End */
        if (pmod->handle && RTLD_NEXT != pmod->handle)
        {
            dlclose(pmod->handle);
            pmod->handle = NULL;
        }
        return -1;
    }
    val.handle = pmod->handle;
    val.type = pKeys->modInx;
    val.event_cb = nstack_epoll_event_enqueue;
    if (stack_register_fn(&pmod->ops, &val, &nstack_fd_deal[pmod->modInx]))
    {
        NSSOC_LOGERR("register function failed");
        if (pmod->handle && RTLD_NEXT != pmod->handle)
        {
            dlclose(pmod->handle);
            pmod->handle = NULL;
        }
        return -1;
    }

    return 0;
}

void nstack_register_module_forchild(void)
{
    ns_uint32 idx;
    for (idx = 0; idx < g_module_num; idx++)
    {
        if (0 !=
            nstack_register_one_module_forchild(&g_nstack_module_desc[idx]))
        {
            NSSOC_LOGERR
                ("can't register module]modInx=%d,modName=%s,libPath=%s",
                 g_nstack_module_desc[idx].modInx,
                 g_nstack_module_desc[idx].modName,
                 g_nstack_module_desc[idx].libPath);
            return;
        }
    }
}

int nstack_register_one_module(nstack_module_keys * pKeys)
{
    nstack_module *pmod = NULL;
    nstack_stack_register_fn stack_register_fn = NULL;
    nstack_event_ops val = { 0 };
    int ret = 0;

    if (pKeys->modInx >= NSTACK_MAX_MODULE_NUM)
    {
        NSSOC_LOGERR("modeindex overflows]index=%d", pKeys->modInx);
        ret = -1;
        goto err_return;
    }

    pmod = nstack_get_module(pKeys->modInx);

    /*There are some unsafe function ,need to be replace with safe function */
    ret =
        strncpy_s(pmod->modulename, NSTACK_MODULE_NAME_MAX, pKeys->modName,
                  NSTACK_MODULE_NAME_MAX - 1);
    if (EOK != ret)
    {
        NSSOC_LOGERR("strncpy_s failed]ret=%d", ret);
        ret = -1;
        goto err_return;
    }

    pmod->modulename[NSTACK_MODULE_NAME_MAX - 1] = '\0';
    pmod->priority = pKeys->priority;
    pmod->modInx = pKeys->modInx;
    pmod->maxfdid = pKeys->maxfdid;
    pmod->minfdid = pKeys->minfdid;

    if (pKeys->libtype == NSTACK_LIB_LOAD_DYN)
    {
        pmod->handle = dlopen(pKeys->libPath, RTLD_LAZY);
        if (!pmod->handle)
        {
            NSSOC_LOGERR
                ("dlopen failed, lib=%s of module=%s, error string=%s",
                 pKeys->libPath, pKeys->modName, dlerror());
            ret = -1;
            goto err_return;
        }
    }
    else
    {
        pmod->handle = RTLD_DEFAULT;
    }

    stack_register_fn = dlsym(pmod->handle, pKeys->register_fn_name);
    if (!stack_register_fn)
    {
        /* optimize dlopen err print Begin */
        NSSOC_LOGERR("register function not found]err_string=%s", dlerror());
        /* optimize dlopen err print End */
        if (pmod->handle)
        {
            dlclose(pmod->handle);
            pmod->handle = NULL;
        }
        ret = -1;
        goto err_return;
    }
    val.handle = pmod->handle;
    val.type = pKeys->modInx;
    val.event_cb = nstack_epoll_event_enqueue;
    if (stack_register_fn(&pmod->ops, &val, &nstack_fd_deal[pmod->modInx]))
    {
        NSSOC_LOGERR("register function failed, module=%s", pKeys->modName);
        if (pmod->handle)
        {
            dlclose(pmod->handle);
            pmod->handle = NULL;
        }
        ret = -1;
        goto err_return;
    }

    /* malloc length need protect
       malloc parameter type is size_t */

    if (((pmod->maxfdid + 1) < 1)
        || (SIZE_MAX / sizeof(ns_int32) < (pmod->maxfdid + 1)))
    {
        NSSOC_LOGERR("malloc size is wrong]maxfdid=%d", pmod->maxfdid);
        if (pmod->handle)
        {
            dlclose(pmod->handle);
            pmod->handle = NULL;
        }
        ret = -1;
        goto err_return;
    }

    if (nstack_fd_deal[pmod->modInx].module_init_pre)
    {
        ret = nstack_fd_deal[pmod->modInx].module_init_pre((void *)
                                                           g_nsfw_mem_ops,
                                                           (void *)
                                                           g_ring_ops_arry,
                                                           NSFW_MEM_TYPEMAX,
                                                           NSFW_MPOOL_TYPEMAX);
    }

  err_return:
    return ret;
}

/*nstack_register_module can't concurrent*/
int nstack_register_module()
{
    unsigned int idx = 0;
    nstack_rd_stack_info *pstacks = NULL;
    int ret = 0;

    pstacks =
        (nstack_rd_stack_info *) malloc(sizeof(nstack_rd_stack_info) *
                                        g_module_num);
    if (!pstacks)
    {
        NSSOC_LOGERR("malloc failed]");
        return ns_fail;
    }
    /*There are some unsafe function ,need to be replace with safe function */
    ret =
        memset_s(&nstack_fd_deal[0], sizeof(nstack_fd_deal), 0,
                 sizeof(nstack_fd_deal));
    ret |=
        memset_s(pstacks, sizeof(nstack_rd_stack_info) * g_module_num, 0,
                 sizeof(nstack_rd_stack_info) * g_module_num);
    if (EOK != ret)
    {
        NSSOC_LOGERR("memset_s failed]ret=%d", ret);
        free(pstacks);          /*free() can be used */
        return ns_fail;
    }

    for (idx = 0; idx < g_module_num; idx++)
    {
        if (0 != nstack_register_one_module(&g_nstack_module_desc[idx]))
        {
            NSSOC_LOGERR
                ("can't register module]modInx=%d,modName=%s,libPath=%s",
                 g_nstack_module_desc[idx].modInx,
                 g_nstack_module_desc[idx].modName,
                 g_nstack_module_desc[idx].libPath);
            free(pstacks);      /*free() can be used */
            return ns_fail;
        }
        ret =
            strcpy_s(pstacks[idx].name, STACK_NAME_MAX,
                     g_nstack_module_desc[idx].modName);
        if (EOK != ret)
        {
            NSSOC_LOGERR("strcpy_s fail]idx=%u,modName=%s,ret=%d", idx,
                         g_nstack_module_desc[idx].modName, ret);
            free(pstacks);      /*free() can be used */
            return ns_fail;
        }

        pstacks[idx].priority = g_nstack_module_desc[idx].priority;
        pstacks[idx].stack_id = g_nstack_module_desc[idx].modInx;
        if (g_nstack_module_desc[idx].default_stack == 1)
        {
            g_nstack_modules.defMod =
                &g_nstack_modules.modules[g_nstack_module_desc[idx].modInx];
            g_nstack_modules.fix_mid = g_nstack_module_desc[idx].modInx;
        }
        if (strcmp(g_nstack_module_desc[idx].modName, RD_KERNEL_NAME) == 0)
        {
            g_nstack_modules.linuxmid = idx;
        }
    }

    if (g_nstack_modules.fix_mid < 0)
    {
        free(pstacks);
        NSSOC_LOGERR("nstack fix mid still unknown!");
        return ns_fail;
    }
    g_nstack_modules.modNum = g_module_num;

    /*rd module init */
    if (ns_success != nstack_rd_init(pstacks, idx))
    {
        free(pstacks);          /*free() can be used */
        NSSOC_LOGERR("nstack rd init fail");
        return ns_fail;
    }
    free(pstacks);              /*free() can be used */
    return ns_success;
}

int nstack_stack_module_init()
{
    int icnt;
    for (icnt = 0; icnt < g_module_num; icnt++)
    {
        if (nstack_fd_deal[icnt].module_init)
        {
            if (nstack_fd_deal[icnt].module_init())
            {
                NSSOC_LOGERR("stack:%s init failed!",
                             g_nstack_modules.modules[icnt].modulename);
                return -1;
            }
        }
        if (nstack_fd_deal[icnt].get_ip_shmem)
        {
            g_rd_table_handle[icnt] =
                (rd_route_table *) nstack_fd_deal[icnt].get_ip_shmem();
        }
    }
    return 0;
}
