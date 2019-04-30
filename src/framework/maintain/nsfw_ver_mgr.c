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

#include <stdlib.h>
#include "types.h"
#include "nstack_securec.h"
#include "nsfw_init_api.h"
#include "nstack_log.h"
#include "nsfw_maintain_api.h"
#include "nsfw_mem_api.h"

nsfw_ver_info g_ver_info;

int g_cur_upg_state = 0;
int g_start_type = 0;

#define NSFW_VER_UPG_KILL_TIME 5

u8 nsfw_init_version_info(u8 proc_type)
{
    int retVal;
    char *module_name = nsfw_get_proc_name(proc_type);
    if (NULL == module_name)
    {
        return FALSE;
    }

    retVal =
        strcpy_s(g_ver_info.module_name, NSTACK_MAX_MODULE_LEN, module_name);
    if (EOK != retVal)
    {
        NSFW_LOGERR("strcpy_s failed]ret=%d.", retVal);
        return FALSE;
    }

    /* `sizeof(constant string) -1` equals to `strlen(constant string)` */
    retVal = strcpy_s(g_ver_info.version, NSTACK_MAX_VERSION_LEN, NSTACK_GETVER_VERSION);       //remove needless 'count' param and change strncpy_s to strcpy_s
    if (EOK != retVal)
    {
        NSFW_LOGERR("strncpy_s failed]ret=%d.", retVal);
        return FALSE;
    }

    retVal = strcpy_s(g_ver_info.build_time, NSTACK_MAX_BUILDTIME_LEN, NSTACK_GETVER_BUILDTIME);        //remove needless 'count' param and change strncpy_s to strcpy_s
    if (EOK != retVal)
    {
        NSFW_LOGERR("strncpy_s failed]ret=%d.", retVal);
        return FALSE;
    }
    NSFW_LOGINF("init version]daemon-stack_version=%s", NSTACK_VERSION);
    return TRUE;
}

/*****************************************************************************
*   Prototype    : nsfw_srv_ctrl_send
*   Description  : send service control message
*   Input        : nsfw_srv_ctrl_state state
*   Output       : None
*   Return Value : u8
*   Calls        :
*   Called By    :
*****************************************************************************/
u8 nsfw_srv_ctrl_send(nsfw_srv_ctrl_state state, u8 rsp_flag)
{
    nsfw_mgr_msg *req_msg =
        nsfw_mgr_msg_alloc(MGR_MSG_SRV_CTL_REQ, NSFW_PROC_MASTER);
    if (NULL == req_msg)
    {
        NSFW_LOGERR("alloc req msg failed]state=%d", state);
        return FALSE;
    }

    nsfw_mgr_msg *rsp_msg = NULL;
    if (TRUE == rsp_flag)
    {
        rsp_msg = nsfw_mgr_null_rspmsg_alloc();
        if (NULL == rsp_msg)
        {
            nsfw_mgr_msg_free(req_msg);
            NSFW_LOGERR("alloc rsp msg failed]state=%d", state);
            return FALSE;
        }
    }

    nsfw_srv_ctrl_msg *ctrl_msg = GET_USER_MSG(nsfw_srv_ctrl_msg, req_msg);
    ctrl_msg->srv_state = state;

    u8 ret;
    ret = nsfw_mgr_send_req_wait_rsp(req_msg, rsp_msg);
    NSFW_LOGINF("send srv ctrl end msg]state=%d,ret=%u,rsp=%u", state, ret,
                rsp_flag);
    nsfw_mgr_msg_free(req_msg);
    if (NULL != rsp_msg)
    {
        nsfw_mgr_msg_free(rsp_msg);
    }
    return ret;
}

/*****************************************************************************
*   Prototype    : nsfw_ver_mgr_rsq
*   Description  : send version mgr message
*   Input        : u16 rsp_code
*   Output       : None
*   Return Value : u8
*   Calls        :
*   Called By    :
*****************************************************************************/
u8 nsfw_ver_mgr_rsq(u16 rsp_code, u32 src_pid)
{
    nsfw_mgr_msg *rsp_msg =
        nsfw_mgr_msg_alloc(MGR_MSG_VER_MGR_RSP, NSFW_PROC_CTRL);
    if (NULL == rsp_msg)
    {
        NSFW_LOGERR("alloc rsp msg failed]rsp_code=%u", rsp_code);
        return FALSE;
    }

    rsp_msg->dst_pid = src_pid;
    if (rsp_code != 0)
    {
        g_cur_upg_state = 0;
    }

    nsfw_ver_mgr_msg *ver_msg = GET_USER_MSG(nsfw_ver_mgr_msg, rsp_msg);
    ver_msg->rsp_code = rsp_code;
    (void) nsfw_mgr_send_msg(rsp_msg);
    nsfw_mgr_msg_free(rsp_msg);
    NSFW_LOGINF("send ver mgr rsp msg]state=%u", rsp_code);
    return TRUE;
}

/*****************************************************************************
*   Prototype    : nsfw_ver_mgr_req
*   Description  : send ver mgr request message
*   Input        : nsfw_ver_mgr_state state
*                  char *src_ver
*                  char* dst_ver
*   Output       : None
*   Return Value : u8
*   Calls        :
*   Called By    :
*****************************************************************************/
u8 nsfw_ver_mgr_req(nsfw_ver_mgr_state state, char *src_ver, char *dst_ver)
{
    nsfw_mgr_msg *req_msg =
        nsfw_mgr_msg_alloc(MGR_MSG_VER_MGR_REQ, NSFW_PROC_MAIN);
    if (NULL == req_msg)
    {
        NSFW_LOGERR("alloc rsp msg failed]state=%d", state);
        return FALSE;
    }

    nsfw_ver_mgr_msg *ver_msg = GET_USER_MSG(nsfw_ver_mgr_msg, req_msg);
    ver_msg->ver_state = state;

    /* we'd better use `strlen(src)` or `sizeof(dst)` to explain copying length of src string.
       it's meaningless using `sizeof(dst) - 1` to reserve 1 byte for '\0'.
       if copying length equals to or bigger than dst length, just let strncpy_s() returns failure. */
    int retVal;
    retVal = strcpy_s(ver_msg->src_ver, NSTACK_MAX_VERSION_LEN, src_ver);       //remove needless 'count' param and change strncpy_s to strcpy_s
    if (EOK != retVal)
    {
        NSFW_LOGERR("strncpy_s failed]ret=%d.", retVal);
        nsfw_mgr_msg_free(req_msg);
        return FALSE;
    }

    retVal = strcpy_s(ver_msg->dst_ver, NSTACK_MAX_VERSION_LEN, dst_ver);       //remove needless 'count' param and change strncpy_s to strcpy_s
    if (EOK != retVal)
    {
        NSFW_LOGERR("strncpy_s failed]ret=%d.", retVal);
        nsfw_mgr_msg_free(req_msg);
        return FALSE;
    }

    (void) nsfw_mgr_send_msg(req_msg);
    nsfw_mgr_msg_free(req_msg);
    NSFW_LOGINF("send srv ctrl end msg]state=%d", state);
    return TRUE;
}

/*****************************************************************************
*   Prototype    : nsfw_ver_mgr_msg_proc
*   Description  : version info query message process
*   Input        : nsfw_mgr_msg* msg
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nsfw_ver_mgr_msg_proc(nsfw_mgr_msg * msg)
{
    if (NULL == msg)
    {
        NSFW_LOGERR("msg nul");
        return FALSE;
    }

    nsfw_ver_mgr_msg *ver_mgr_msg = GET_USER_MSG(nsfw_ver_mgr_msg, msg);
    NSFW_LOGDBG("recv ver mgr msg]state=%d,src_ver=%s,dst_ver=%s",
                ver_mgr_msg->ver_state, ver_mgr_msg->src_ver,
                ver_mgr_msg->dst_ver);

    if (NSFW_VER_QRY == ver_mgr_msg->ver_state)
    {
        nsfw_mgr_msg *rsp_msg = nsfw_mgr_rsp_msg_alloc(msg);
        if (NULL == rsp_msg)
        {
            NSFW_LOGERR("alloc rsp failed,drop msg!" MSGINFO, PRTMSG(msg));
            return FALSE;
        }

        nsfw_ver_mgr_msg *ver_rsp_msg =
            GET_USER_MSG(nsfw_ver_mgr_msg, rsp_msg);

        /* we'd better use `strlen(src)` or `sizeof(dst)` to explain copying length of src string.
           it's meaningless using `sizeof(dst) - 1` to reserve 1 byte for '\0'.
           if copying length equals to or bigger than dst length, just let strncpy_s() returns failure. */

        /* change strncpy_s's param 'count' from XXX to XXX-1 */
        int retVal;
        retVal = strcpy_s(ver_rsp_msg->module_name, NSTACK_MAX_MODULE_LEN, g_ver_info.module_name);     //remove needless 'count' param and change strncpy_s to strcpy_s
        if (EOK != retVal)
        {
            NSFW_LOGERR("strncpy_s failed]ret=%d.", retVal);
            nsfw_mgr_msg_free(rsp_msg);
            return FALSE;
        }

        retVal = strcpy_s(ver_rsp_msg->src_ver, NSTACK_MAX_VERSION_LEN, g_ver_info.version);    //remove needless 'count' param and change strncpy_s to strcpy_s
        if (EOK != retVal)
        {
            NSFW_LOGERR("strncpy_s failed]ret=%d.", retVal);
            nsfw_mgr_msg_free(rsp_msg);
            return FALSE;
        }

        retVal = strcpy_s(ver_rsp_msg->build_time, NSTACK_MAX_BUILDTIME_LEN, g_ver_info.build_time);    //remove needless 'count' param and change strncpy_s to strcpy_s
        if (EOK != retVal)
        {
            NSFW_LOGERR("strncpy_s failed]ret=%d.", retVal);
            nsfw_mgr_msg_free(rsp_msg);
            return FALSE;
        }

        ver_rsp_msg->ver_state = ver_mgr_msg->ver_state;
        (void) nsfw_mgr_send_msg(rsp_msg);
        nsfw_mgr_msg_free(rsp_msg);
    }

    return TRUE;
}

/*****************************************************************************
*   Prototype    : nsfw_ver_mgr_upg_msg_proc
*   Description  : master upg
*   Input        : nsfw_mgr_msg* msg
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nsfw_ver_mgr_upg_msg_proc(nsfw_mgr_msg * msg)
{
    if (NULL == msg)
    {
        NSFW_LOGERR("msg nul");
        return FALSE;
    }

    nsfw_ver_mgr_msg *ver_mgr_msg = GET_USER_MSG(nsfw_ver_mgr_msg, msg);        /*not redeclared */
    NSFW_LOGDBG("recv ver mgr msg]state=%d,src_ver=%s,dst_ver=%s",
                ver_mgr_msg->ver_state, ver_mgr_msg->src_ver,
                ver_mgr_msg->dst_ver);

    if ((NSFW_VER_UPG != ver_mgr_msg->ver_state)
        && (NSFW_VER_RBK != ver_mgr_msg->ver_state))
    {
        return FALSE;
    }

    if (TRUE == nsfw_ver_mgr_rsq(0, msg->src_pid))
    {
        int i = 0;
        while (i < NSFW_VER_UPG_KILL_TIME)
        {
            NSFW_LOGINF("wait nStackKill!]i=%d", i);
            (void) sleep(1);
            i++;
        }

        exit(0);
    }
    return TRUE;
}

u8 nsfw_init_result_send(u8 local_proc, nsfw_init_state state, u8 rsp_flag)
{
    nsfw_mgr_msg *req_msg =
        nsfw_mgr_msg_alloc(MGR_MSG_INIT_NTY_REQ, NSFW_PROC_MASTER);
    if (NULL == req_msg)
    {
        NSFW_LOGERR("alloc req msg failed]state=%d", state);
        return FALSE;
    }

    nsfw_mgr_msg *rsp_msg = NULL;
    if (TRUE == rsp_flag)
    {
        rsp_msg = nsfw_mgr_rsp_msg_alloc(req_msg);
        if (NULL == rsp_msg)
        {
            NSFW_LOGERR("alloc rsp msg failed]state=%d", state);
            nsfw_mgr_msg_free(req_msg);
            return FALSE;
        }
    }

    if (TRUE == req_msg->from_mem)
    {
        req_msg->src_proc_type = local_proc;
    }

    nsfw_init_nty_msg *init_msg = GET_USER_MSG(nsfw_init_nty_msg, req_msg);
    init_msg->init_state = state;

    u8 ret;
    ret = nsfw_mgr_send_req_wait_rsp(req_msg, rsp_msg);
    NSFW_LOGINF("send init end msg]state=%d,ret=%u,rsp=%u", state, ret,
                rsp_flag);
    nsfw_mgr_msg_free(req_msg);
    if (NULL != rsp_msg)
    {
        nsfw_mgr_msg_free(rsp_msg);
    }

    return ret;
}

int nsfw_vermgr_module_init(void *param);
int nsfw_vermgr_module_init(void *param)
{
    u8 proc_type = (u8) ((long long) param);
    if (proc_type != NSFW_PROC_CTRL)
    {
        NSFW_LOGINF("verupg module init]type=%d", proc_type);
    }
    (void) nsfw_init_version_info(proc_type);
    switch (proc_type)
    {
        case NSFW_PROC_MASTER:
            (void) nsfw_mgr_reg_msg_fun(MGR_MSG_VER_MGR_REQ,
                                        nsfw_ver_mgr_upg_msg_proc);
            (void) nsfw_mgr_reg_msg_fun(MGR_MSG_VER_MGR_REQ,
                                        nsfw_ver_mgr_msg_proc);
            return 0;
        case NSFW_PROC_MAIN:
        case NSFW_PROC_CTRL:
            (void) nsfw_mgr_reg_msg_fun(MGR_MSG_VER_MGR_REQ,
                                        nsfw_ver_mgr_msg_proc);
            return 0;
        default:
            if (proc_type < NSFW_PROC_MAX)
            {
                break;
            }
            return -1;
    }

    return 0;
}

/* *INDENT-OFF* */
NSFW_MODULE_NAME(NSFW_VER_MGR_MODULE)
NSFW_MODULE_PRIORITY(99)
NSFW_MODULE_INIT(nsfw_vermgr_module_init)
/* *INDENT-ON* */
