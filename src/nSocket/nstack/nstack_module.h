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

#ifndef __NSTACK_MODULE_H__
#define __NSTACK_MODULE_H__

#ifndef SPL_INSTANCE_H
#include <poll.h>
#endif
#include <sys/socket.h>
#include <sys/epoll.h>
#include "types.h"
#include "nstack_callback_ops.h"
#include "nsfw_common_defs.h"

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C"{
/* *INDENT-ON* */
#endif

#define MOD_INDEX_FOR_STACKPOOL  1

typedef struct __NSTACK_MODULE_KEYS
{
    ns_char modName[NSTACK_MODULE_NAME_MAX];    // stack name
    ns_char register_fn_name[NSTACK_MODULE_NAME_MAX];   // stack register function symbol
    ns_char libPath[NSTACK_MODULE_NAME_MAX];    // if libtype is dynamic, it is the path of lib
    ns_char deploytype;         // deploy type: type1, type2, type3, and etc
    ns_char libtype;            // dynamic or static
    ns_char default_stack;      // whether it is the default one
    ns_int32 priority;
    ns_int32 maxfdid;           //the max fd id
    ns_int32 minfdid;           //the min fd id
    ns_int32 modInx;            // This is alloced by nStack , not from configuration
} nstack_module_keys;

typedef struct __NSTACK_MODULE
{
    char modulename[NSTACK_MODULE_NAME_MAX];
    ns_int32 priority;
    void *handle;
    nstack_socket_ops ops;
    ns_int32 modInx;            // The index of module
    ns_int32 maxfdid;           //the max fd id
    ns_int32 minfdid;           //the min fd id
} nstack_module;

typedef struct
{
    ns_int32 modNum;            // Number of modules registed
    ns_int32 fix_mid;
    ns_int32 linuxmid;
    nstack_module *defMod;      // The default module
    nstack_module modules[NSTACK_MAX_MODULE_NUM];
} nstack_module_info;

typedef enum
{
    NSTACK_MODEL_TYPE1 = 1,     /*nSocket and stack belong to the same process */
    NSTACK_MODEL_TYPE2 = 2,     /*nSocket and stack belong to different processes,
                                 *and nStack don't take care the communication between stack and stack adpt
                                 */
    NSTACK_MODEL_TYPE3 = 3,     /*nSocket and stack belong to different processes, and sbr was supplied to communicate whit stack */
    NSTACK_MODEL_TYPE_SIMPLE_STACK = 4, /* like TYPE1, DMM will NOT provide SBR or pipeline mode, just allocate 32M, and use dpdk file
                                         * prefix to support multiple running app under DMM */
    NSTACK_MODEL_INVALID,
} nstack_model_deploy_type;

/*register module according the modulecfg file*/
extern ns_int nstack_register_module();

/*****************************************************************
Parameters    :  ops never be null;  nstack api calls it;
Return        :    0,not match; 1, match
Description   :
*****************************************************************/
extern nstack_module_info g_nstack_modules;
extern nstack_proc_ops nstack_fd_deal[NSTACK_MAX_MODULE_NUM];
extern nstack_module_keys g_nstack_module_desc[];
extern ns_uint32 g_module_num;

#define nstack_defmod_name() (g_nstack_modules.defMod->modulename)
#define nstack_default_module() (g_nstack_modules.defMod)
#define nstack_defmod_inx() (g_nstack_modules.fix_mid)
#define nstack_get_module(inx) (&g_nstack_modules.modules[(inx)])
#define nstack_get_module_num() (g_nstack_modules.modNum)
#define nstack_get_module_name_by_idx(inx) (g_nstack_modules.modules[inx].modulename)
#define nstack_def_ops() (&g_nstack_modules.defMod->ops)
#define nstack_get_linux_mid() (g_nstack_modules.linuxmid)
#define nstack_module_ops(modInx) (&g_nstack_modules.modules[(modInx)].ops)

#define nstack_get_maxfd_id(modInx) (g_nstack_modules.modules[modInx].maxfdid)
#define nstack_get_minfd_id(modInx) (g_nstack_modules.modules[modInx].minfdid)
#define nstack_set_maxfd_id(modInx, maxfd) (g_nstack_module_desc[modInx].maxfdid = maxfd)

#define nstack_def_mod_profd(fdInf) ((fdInf)->protoFD[g_nstack_modules.defMod->modInx].fd)
#define nstack_inf_mod_profd(fdInf, pMod) ((fdInf)->protoFD[(pMod)->modInx].fd)

#define nstack_each_mod_ops(modInx, ops)  \
    for ((modInx) = 0; ((modInx) < nstack_get_module_num() && ((ops) = nstack_module_ops(modInx))); (modInx)++)

#define nstack_each_mod_inx(modInx) \
    for ((modInx) = 0; ((modInx) < nstack_get_module_num()); (modInx)++)

#define nstack_each_module(modInx, pMod) \
        for ((modInx) = 0; ((modInx) < nstack_get_module_num() && (pMod = nstack_get_module((modInx)))); (modInx)++)

void nstack_register_module_forchild(void);
int nstack_get_deploy_type();
int nstack_stack_module_init();

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif /* __NSTACK_MODULE_H__ */
