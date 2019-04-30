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
#include <string.h>
#include "nstack_securec.h"
#include "nsfw_init_api.h"
#include "fw_module.h"
#include "nstack_log.h"

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C"{
/* *INDENT-ON* */
#endif /* __cplusplus */

int g_fw_init_err = 0;
int get_fw_init_err()
{
    return g_fw_init_err;
}

void set_fw_init_err(int x)
{
    g_fw_init_err = x;
}

NSTACK_STATIC int nsfw_module_instance_is_independ(nsfw_module_instance_t *
                                                   inst)
{
    nsfw_module_depends_t *dep = inst->depends;
    while (dep)
    {
        if (!dep->isReady)
            return 1;
        dep = dep->next;
    }

    return 0;
}

NSTACK_STATIC void nsfw_module_instance_depend_check(nsfw_module_instance_t *
                                                     inst)
{
    nsfw_module_instance_t *curInst = nsfw_module_get_manager()->inst;
    while (curInst)
    {
        if (curInst == inst)
            goto nextLoop;
        if (NSFW_INST_STAT_CHECKING == curInst->stat
            || NSFW_INST_STAT_DEPENDING == curInst->stat)
        {
            nsfw_module_depends_t *dep = curInst->depends;
            while (dep)
            {
                if (0 == dep->isReady && 0 == strcmp(dep->name, inst->name))
                {
                    dep->isReady = 1;   /*  Don't break for case that duplicate name exist, though I think it should
                                           not happen */
                }
                dep = dep->next;
            }
        }
      nextLoop:                /*this type usually use like this and no "space" */
        curInst = curInst->next;
    }

}

NSTACK_STATIC int nstack_framework_init_child_unsafe(nsfw_module_instance_t *
                                                     father)
{
    NSFW_LOGDBG("init framework module] name=%s",
                father ? father->name : "NULL");

    nsfw_module_instance_t *inst = nsfw_module_get_manager()->inst;
    int initRet = 0;
    while (inst)
    {
        NSFW_LOGDBG
            ("init child] inst=%s, inst->father=%s, inst->depends=%s, inst->state=%d",
             inst->name, inst->father ? inst->father->name : "NULL",
             inst->depends ? inst->depends->name : "NULL", inst->stat);

        if (father != inst->father)
        {
            NSFW_LOGDBG("inst->father not match] inst=%s, ", inst->name);

            inst = inst->next;
            continue;
        }

        switch (inst->stat)
        {
            case NSFW_INST_STAT_CHECKING:
                /* First, check if any depends, then check if other instance depends on it */
                if (nsfw_module_instance_is_independ(inst))
                {
                    inst->stat = NSFW_INST_STAT_DEPENDING;
                    NSFW_LOGDBG("inst is still depending] name=%s",
                                inst->name);
                    inst = inst->next;
                    break;
                }

                NSFW_LOGINF("Going to init module]name=%s,init fun=%p",
                            inst->name, inst->fnInit);
                if (NULL != inst->fnInit
                    && 0 != (initRet = inst->fnInit(inst->param)))
                {
                    NSFW_LOGERR("initial fail]inst=%s,initRet=%d",
                                inst->name, initRet);
                    inst->stat = NSFW_INST_STAT_FAIL;
                    if (get_fw_init_err() == 0) /* record first init err */
                    {
                        NSFW_LOGERR("update g_fw_init_err to %d", initRet);
                        /* TODO: now g_fw_init_err conveys errcode and be processed in master_main,
                         * better way is to regsiter an error-handler for each inst */
                        set_fw_init_err(initRet);
                    }
                    return -1;
                }

                inst->stat = NSFW_INST_STAT_DONE;
                nsfw_module_instance_depend_check(inst);

                if (-1 == nsfw_module_add_done_node(inst))
                {
                    NSFW_LOGERR("add done node fail");
                }

                inst = nsfw_module_get_manager()->inst; /* check from begining */
                break;
            case NSFW_INST_STAT_DEPENDING:
                /* check if depending stat is still there */
                if (!nsfw_module_instance_is_independ(inst))
                {
                    inst->stat = NSFW_INST_STAT_CHECKING;
                    break;
                }
            case NSFW_INST_STAT_FAIL:
            case NSFW_INST_STAT_DONE:
            default:
                inst = inst->next;
                break;
        }
    }

    return 0;
}

NSTACK_STATIC
    void nstack_framework_print_instance_info(nsfw_module_instance_t * inst)
{

    if (NULL == inst)
    {
        NSFW_LOGERR("param err]inst=NULL");
        return;
    }

    char info[1000] = "";
    int plen = 0;

    int ret = sprintf_s(info, sizeof(info), "Inst:%s,father:%s,depends:",
                        inst->name,
                        inst->father ? inst->father->name : "NULL");

    if (ret <= 0)
    {
        NSFW_LOGERR("Sprintf err]module=%s,state=%d,ret=%d", inst->name,
                    inst->stat, ret);
        return;
    }
    else
    {
        plen += ret;
    }

    if (NULL == inst->depends)
    {
        ret = sprintf_s(info + plen, sizeof(info) - plen, "NULL");
        if (ret <= 0)
        {
            NSFW_LOGERR("Sprintf Err]module=%s,state=%d,ret=%d", inst->name,
                        inst->stat, ret);
            return;
        }
        NSFW_LOGINF("]inst info=%s", info);
        return;
    }

    nsfw_module_depends_t *dep = inst->depends;
    while (dep && (plen < (int) sizeof(info)))
    {
        ret = sprintf_s(info + plen, sizeof(info) - plen, "%s ", dep->name);
        if (ret <= 0)
        {
            NSFW_LOGERR("Sprintf Err]module=%s,state=%d,ret=%d", inst->name,
                        inst->stat, ret);
            return;
        }
        plen += ret;
        dep = dep->next;
    }

    NSFW_LOGINF("]inst info=%s", info);
}

NSTACK_STATIC void nstack_framework_print_initial_result()
{
    nsfw_module_manager_t *manager = nsfw_module_get_manager();

    if (manager->doneHead)
    {
        NSFW_LOGINF("Here is the initial done modules: ");

        nsfw_module_done_node_t *curNode = manager->doneHead;
        while (curNode)
        {
            nstack_framework_print_instance_info(curNode->inst);
            curNode = curNode->next;
        }
    }
    else
    {
        NSFW_LOGERR("No initial done modules");
    }

    nsfw_module_instance_t *curInst = manager->inst;
    int unDoneNum = 0;
    while (curInst)
    {
        if (curInst->stat != NSFW_INST_STAT_DONE)
        {
            if (0 == unDoneNum)
            {
                NSFW_LOGINF("Here is the unInited modules:");
            }
            unDoneNum++;
            nstack_framework_print_instance_info(curInst);
        }
        curInst = curInst->next;
    }
    if (0 == unDoneNum)
        NSFW_LOGINF("All modules are inited");
}

/**
 * @Function        nstack_framework_init
 * @Description     This function will do framework initial work, it will involk all initial functions
 *                      registed using macro NSFW_MODULE_INIT before
 * @param           none
 * @return          0 on success, -1 on error
 */
int nstack_framework_init(void)
{
    int ret = -1;
    if (nsfw_module_get_manager()->done)
    {
        goto init_finished;
    }

    if (pthread_mutex_lock(&nsfw_module_get_manager()->initMutex))
    {
        return -1;
    }

    if (nsfw_module_get_manager()->done)
    {
        goto done;
    }

    ret = nstack_framework_init_child_unsafe(NULL);

    if (0 == ret)
    {
        nsfw_module_get_manager()->done = 1;
    }
    else
    {
        nsfw_module_get_manager()->done = -1;
    }

    // Going to print done modules and undone modules
    nstack_framework_print_initial_result();

  done:
    if (pthread_mutex_unlock(&nsfw_module_get_manager()->initMutex))
    {
        return -1;
    }
  init_finished:
    ret = nsfw_module_get_manager()->done == 1 ? 0 : -1;
    return ret;
}

/**
 * @Function        nstack_framework_set_module_param
 * @Description     This function set parameter of module initial function parameter
 * @param           module - name of module
 * @param           param - parameter to set
 * @return          0 on success, -1 on error
 */
int nstack_framework_set_module_param(char *module, void *param)
{
    nsfw_module_instance_t *inst = nsfw_module_get_module_by_name(module);
    if (!inst)
        return -1;

    inst->param = param;
    return 0;
}

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif /* __cplusplus */
