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

#include "nsfw_mgr_com_api.h"
#include "mgr_com.h"
#include "nsfw_alarm_api.h"
#include "nsfw_ps_api.h"
#include "nsfw_ps_module.h"
#include "nsfw_mem_api.h"
#include "nstack_log.h"
#include "nsfw_base_linux_api.h"
#include "nsfw_fd_timer_api.h"
#include "nsfw_maintain_api.h"

#include <errno.h>
#include <sys/un.h>
#include <stddef.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <dirent.h>
#include <fnmatch.h>

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C"{
/* *INDENT-ON* */
#endif /* __cplusplus */

nsfw_ps_init_cfg g_ps_cfg;

nsfw_pid_item *g_ps_info = NULL;

nsfw_pid_item *g_master_ps_info = NULL;

struct list_head g_ps_runing_list;
nsfw_ps_callback g_ps_init_callback[NSFW_PROC_MAX][NSFW_PS_MAX_CALLBACK];
nsfw_ps_info g_main_ps_info;

extern nsfw_mgr_init_cfg g_mgr_com_cfg;

void *g_ps_chk_timer = NULL;

/* keep count of processes being in EXITING state */
u32 g_ps_exiting_cnt = 0;
NSTACK_STATIC void inc_ps_exiting_cnt();
NSTACK_STATIC void dec_ps_exiting_cnt();

typedef struct _omc_alarm_status
{
    char send_succ_flag;
    alarm_flag current_alarm_state;
    nsfw_timer_info *resend_timer;
} omc_alarm_stat;

#define SCRIPT_NS_CTL_SND_NSMAIN_NOR_ALM  "./nStackCtrl --module alm -n nsMain -t normal"
#define SCRIPT_NS_CTL_SND_NSMAIN_ABNOR_ALM  "./nStackCtrl --module alm -n nsMain -t abnormal"
#define SCRIPT_NS_CTL_SND_NSMAIN_START  "./nStackCtrl --module alm -n nsMain -t normalStart"
#define SCRIPT_NS_CTL_SND_NSMAIN_EXIT  "./nStackCtrl --module alm -n nsMain -t abnormalExit"

#define MASTER_RESEND_NSMAIN_TIMER 1

omc_alarm_stat g_omc_alm_state[ALARM_EVENT_MAX];

typedef struct _omc_hf_alarm_status
{
    nsfw_timer_info *resend_timer;
    hotfix_res res;
} omc_hf_alarm_stat;
omc_hf_alarm_stat g_omc_hf_alm_state;
#define MASTER_RESEND_HOTFIX_TIMER 1

const char *omc_get_nstackctrl_alarm_string(enum_alarm_id alarm_id,
                                            alarm_flag alarm_state)
{
    const char *alarm_script = NULL;

    switch (alarm_id)
    {
        case ALARM_EVENT_NSTACK_MAIN_ABNORMAL_RESTART_FAIL:

            if (ALARM_PRODUCT == alarm_state)
            {
                alarm_script = SCRIPT_NS_CTL_SND_NSMAIN_ABNOR_ALM;
            }
            else
            {
                alarm_script = SCRIPT_NS_CTL_SND_NSMAIN_NOR_ALM;
            }

            break;
        case ALARM_EVENT_NSTACK_MAIN_EXIT_CAUSE_FD_FAIL:

            if (ALARM_PRODUCT == alarm_state)
            {
                alarm_script = SCRIPT_NS_CTL_SND_NSMAIN_EXIT;
            }
            else
            {
                alarm_script = SCRIPT_NS_CTL_SND_NSMAIN_START;
            }

            break;
        default:
            NSAM_LOGERR("alarm_id is invalid");
            break;
    }

    return alarm_script;

}

/* should send restore alarm when daemon-stack restart successfully*/
int omc_resend_nsmain_alarm(u32 timer_type, void *argv)
{
#define TMP_RESULT_BUF_LEN 128

    int retval;
    char result[TMP_RESULT_BUF_LEN] = { 0 };
    int rt_len;
    const char *alarm_script = NULL;
    enum_alarm_id tmp_alarm_id = (enum_alarm_id) argv;
    omc_alarm_stat *tmp_alarm_stat = NULL;

    if (ALARM_ID_NOT_VALID(tmp_alarm_id))
    {
        NSAM_LOGERR("alarm_id is invalid");
        return 0;
    }

    tmp_alarm_stat = &g_omc_alm_state[tmp_alarm_id];

    /* when timeout, need clear */
    tmp_alarm_stat->resend_timer = NULL;

    alarm_script =
        omc_get_nstackctrl_alarm_string(tmp_alarm_id,
                                        tmp_alarm_stat->current_alarm_state);

    if (NULL == alarm_script)
    {
        NSAM_LOGERR("get alarm_script fail");
        return 0;
    }

    if (0 != tmp_alarm_stat->send_succ_flag)
    {
        rt_len =
            nsfw_mgr_run_script(alarm_script, result, TMP_RESULT_BUF_LEN);
        if (0 == rt_len || -1 == rt_len || (!nsfw_isdigitstr(result)))  //also check return -1
        {
            retval = -1;
        }
        else
        {
            retval = atoi(result);
        }
        tmp_alarm_stat->send_succ_flag = retval;

        if (0 == tmp_alarm_stat->send_succ_flag)
        {
            NSAM_LOGINF("send alarm success]alarm_id=%u,alarm_status=%u",
                        tmp_alarm_id + ALARM_ID_BASE_VALUE,
                        tmp_alarm_stat->current_alarm_state);
        }
        else
        {
            NSAM_LOGINF("send alarm fail]alarm_id=%u,alarm_status=%u",
                        tmp_alarm_id + ALARM_ID_BASE_VALUE,
                        tmp_alarm_stat->current_alarm_state);
            /* only when send fail, start resend timer */
            struct timespec alarm_resend_time =
                { ALARM_RESEND_TIMER_LENGTH, 0 };
            tmp_alarm_stat->resend_timer =
                nsfw_timer_reg_timer(MASTER_RESEND_NSMAIN_TIMER,
                                     (void *) tmp_alarm_id,
                                     omc_resend_nsmain_alarm,
                                     alarm_resend_time);
            if (NULL == tmp_alarm_stat->resend_timer)
            {
                NSFW_LOGERR("start alarm resend timer fail");
            }
        }

    }

    return 0;

}

/*****************************************************************************
*   Prototype    : omc_remove_resend_timer_inner
*   Description  : remove alarm resend timer if exist
*   Input        : None
*   Output       : None
*   Return Value : None
*   Calls        :
*   Called By    : omc_send_nsmain_alarm_inner
*****************************************************************************/
NSTACK_STATIC void omc_remove_resend_timer_inner(enum_alarm_id alarm_id)
{
    omc_alarm_stat *tmp_alarm_stat = NULL;
    if (ALARM_ID_NOT_VALID(alarm_id))
    {
        NSAM_LOGERR("alarm_id is invalid");
        return;
    }

    tmp_alarm_stat = &g_omc_alm_state[alarm_id];

    if (NULL == tmp_alarm_stat->resend_timer)
    {
        return;
    }

    nsfw_timer_rmv_timer(tmp_alarm_stat->resend_timer);
    tmp_alarm_stat->resend_timer = NULL;

}

/*****************************************************************************
*   Prototype    : omc_send_nsmain_alarm_inner
*   Description  : omc_send_nsmain_alarm_inner process function
*   Input        : init_status_flag ; alarm_flag alm_flag
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
void omc_send_nsmain_alarm_inner(char init_status_flag,
                                 enum_alarm_id alarm_id, alarm_flag alm_flag)
{
#define TMP_RESULT_BUF_LEN 128
    int retval;
    char result[TMP_RESULT_BUF_LEN] = { 0 };
    int rt_len;
    omc_alarm_stat *tmp_alarm_stat = NULL;

    const char *alarm_script = NULL;

    if (ALARM_ID_NOT_VALID(alarm_id))
    {
        NSAM_LOGDBG("alarm_id is invalid");
        return;
    }

    tmp_alarm_stat = &g_omc_alm_state[alarm_id];

    if (1 != init_status_flag)
    {
        /* only for alarm status change, can send alarm */
        if (alm_flag == tmp_alarm_stat->current_alarm_state)
        {
            NSAM_LOGDBG("same status, can't send alarm");
            return;
        }
    }
    else
    {
        /* init alarm, use current alarm state stored */
        alm_flag = tmp_alarm_stat->current_alarm_state;
    }

    alarm_script = omc_get_nstackctrl_alarm_string(alarm_id, alm_flag);

    if (NULL == alarm_script)
    {
        NSAM_LOGERR("get alarm_script fail");
        return;
    }

    rt_len = nsfw_mgr_run_script(alarm_script, result, TMP_RESULT_BUF_LEN);

    if (0 == rt_len || -1 == rt_len || (!nsfw_isdigitstr(result)))
    {
        retval = -1;
    }
    else
    {
        retval = atoi(result);
    }
    tmp_alarm_stat->current_alarm_state = alm_flag;
    tmp_alarm_stat->send_succ_flag = retval;

    if (0 == tmp_alarm_stat->send_succ_flag)
    {
        NSAM_LOGINF("send alarm success]alarm_id=%d,alarm_status=%d",
                    alarm_id + ALARM_ID_BASE_VALUE,
                    tmp_alarm_stat->current_alarm_state);

        /* when send success, then stop resend timer */
        omc_remove_resend_timer_inner(alarm_id);
    }
    else
    {
        NSAM_LOGINF("send alarm fail]alarm_id=%d,alarm_status=%d",
                    alarm_id + ALARM_ID_BASE_VALUE,
                    tmp_alarm_stat->current_alarm_state);
        struct timespec alarm_resend_time = { ALARM_RESEND_TIMER_LENGTH, 0 };

        /* should clear the old timer before register a new one */
        omc_remove_resend_timer_inner(alarm_id);

        /* only start resend time when send failed */
        tmp_alarm_stat->resend_timer =
            nsfw_timer_reg_timer(MASTER_RESEND_NSMAIN_TIMER,
                                 (void *) (alarm_id),
                                 omc_resend_nsmain_alarm, alarm_resend_time);
        if (NULL == tmp_alarm_stat->resend_timer)
        {
            NSFW_LOGERR("start alarm resend timer fail");
        }
    }

}

void omc_send_init_nsmain_alarm(enum_alarm_id alarm_id)
{
    omc_send_nsmain_alarm_inner(1, alarm_id, ALARM_CLEAN);
}

void omc_send_nsmain_alarm(enum_alarm_id alarm_id, alarm_flag alm_flag)
{
    omc_send_nsmain_alarm_inner(0, alarm_id, alm_flag);
}

/*****************************************************************************
*   Prototype    : omc_remove_hf_resend_timer_inner
*   Description  : remove hotfix alarm resend timer if exist
*   Input        : None
*   Output       : None
*   Return Value : None
*   Calls        :
*   Called By    : omc_send_nsmain_alarm_inner
*****************************************************************************/
NSTACK_STATIC void omc_remove_hf_resend_timer_inner()
{
    if (NULL != g_omc_hf_alm_state.resend_timer)
    {
        nsfw_timer_rmv_timer(g_omc_hf_alm_state.resend_timer);
        g_omc_hf_alm_state.resend_timer = NULL;
    }
}

/*****************************************************************************
*   Prototype    : omc_send_hotfix_alarm_inner
*   Description  :
*   Input        : void
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int omc_send_hotfix_alarm_inner()
{
    int retval;
    int rt_len;
    char alarm_script[512] = { 0 };
    char res_buffer[128] = { 0 };

    retval = sprintf_s(alarm_script, sizeof(alarm_script),
                       "./nStackCtrl --module alm -n hotfix -a %d -r %d -v\"%s\" -p %d",
                       g_omc_hf_alm_state.res.action,
                       g_omc_hf_alm_state.res.result,
                       g_omc_hf_alm_state.res.patch_version,
                       g_omc_hf_alm_state.res.proc_type);
    if (-1 == retval)
    {
        NSAM_LOGERR("sprintf_s fail]ret=%d", retval);
        return -1;
    }

    rt_len =
        nsfw_mgr_run_script(alarm_script, res_buffer, sizeof(res_buffer));
    if (0 == rt_len || -1 == rt_len || (!nsfw_isdigitstr(res_buffer)))
    {
        retval = -1;
    }
    else
    {
        retval = atoi(res_buffer);
    }

    if (0 == retval)
    {
        NSAM_LOGINF("send hotfix alarm success]alarm_id=4");
        /* when send success, then stop resend timer */
        omc_remove_hf_resend_timer_inner();
    }
    else
    {
        NSAM_LOGINF("send hotfix alarm fail]alarm_id=4");
        /* should clear the old timer before register a new one */
        omc_remove_hf_resend_timer_inner();

        struct timespec alarm_resend_time = { ALARM_RESEND_TIMER_LENGTH, 0 };
        /* only start resend time when send failed */
        g_omc_hf_alm_state.resend_timer =
            nsfw_timer_reg_timer(MASTER_RESEND_HOTFIX_TIMER, NULL,
                                 omc_send_hotfix_alarm_inner,
                                 alarm_resend_time);
        if (NULL == g_omc_hf_alm_state.resend_timer)
        {
            NSFW_LOGERR("start hotfix alarm resend timer fail");
        }
    }

    return 0;

}

/*****************************************************************************
*   Prototype    : omc_send_hotfix_alarm
*   Description  : called by hotfix module
*   Input        : void
*   Output       : None
*   Return Value : void
*   Calls        :
*   Called By    :
*****************************************************************************/
void omc_send_hotfix_alarm(int proc_type, int action, int result,
                           const char *version)
{
    g_omc_hf_alm_state.res.proc_type = (fw_poc_type) proc_type;
    g_omc_hf_alm_state.res.action = (hotfix_optype) action;
    g_omc_hf_alm_state.res.result = result;
    int ret = strcpy_s(g_omc_hf_alm_state.res.patch_version,
                       sizeof(g_omc_hf_alm_state.res.patch_version),
                       version);
    if (EOK != ret)
    {
        NSFW_LOGERR("strcpy_s failed]ret=%d", ret);
    }

    (void) omc_send_hotfix_alarm_inner();
}

/* API for another module to get the global */
u32 get_ps_exiting_cnt()
{
    return g_ps_exiting_cnt;
}

/*****************************************************************************
*   Prototype    : inc_ps_exiting_cnt
*   Description  : g_ps_exiting_cnt++
*   Input        : None
*   Output       : None
*   Return Value : None
*   Calls        :
*   Called By    : nsfw_sw_ps_state( ,NSFW_PS_EXITING) ONLY!
*****************************************************************************/
NSTACK_STATIC void inc_ps_exiting_cnt()
{
    if (g_ps_exiting_cnt < NSFW_MAX_PID)
    {
        g_ps_exiting_cnt++;
    }
    else
    {
        NSFW_LOGERR("g_ps_exiting_cnt would exceed NSFW_MAX_PID! now is %u",
                    g_ps_exiting_cnt);
    }
}

/*****************************************************************************
*   Prototype    : dec_ps_exiting_cnt
*   Description  : g_ps_exiting_cnt--
*   Input        : None
*   Output       : None
*   Return Value : None
*   Calls        :
*   Called By    : nsfw_sw_ps_state( ,NSFW_PS_EXIT) ONLY!
*****************************************************************************/
NSTACK_STATIC void dec_ps_exiting_cnt()
{
    if (g_ps_exiting_cnt > 0)
    {
        g_ps_exiting_cnt--;
    }
    else
    {
        NSFW_LOGERR("g_ps_exiting_cnt would drop below zero! now is %u",
                    g_ps_exiting_cnt);
    }
}

/*****************************************************************************
*   Prototype    : nsfw_ps_reg_fun
*   Description  : reg the callback fun when process state change
*   Input        : nsfw_ps_info *pps_info
*                  u8 ps_state
*                  nsfw_ps_proc_fun fun
*                  void* argv
*   Output       : None
*   Return Value : u8
*   Calls        :
*   Called By    :
*****************************************************************************/
u8 nsfw_ps_reg_fun(nsfw_ps_info * pps_info, u8 ps_state,
                   nsfw_ps_proc_fun fun, void *argv)
{
    if (NULL == pps_info)
    {
        NSFW_LOGERR("reg pps_info nul]state=%d,fun=%p", ps_state, fun);
        return FALSE;
    }

    u32 i;
    for (i = 0; i < NSFW_PS_MAX_CALLBACK; i++)
    {
        if (NULL == pps_info->callback[i].fun)
        {
            pps_info->callback[i].fun = fun;
            pps_info->callback[i].argv = argv;
            pps_info->callback[i].state = ps_state;
            NSFW_LOGDBG
                ("reg fun suc]ps_info=%p,state=%d,fun=%p,argv=%p,i=%u",
                 pps_info, ps_state, fun, argv, i);
            return TRUE;
        }
    }

    NSFW_LOGERR("reg fun failed]ps_info=%p,state=%d,fun=%p,argv=%p,i=%u",
                pps_info, ps_state, fun, argv, i);
    return FALSE;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_reg_global_fun
*   Description  : reg the callback function of the specify proc_type state
                   change
*   Input        : u8 proc_type
*                  u8 ps_state
*                  nsfw_ps_proc_fun fun
*                  void* argv
*   Output       : None
*   Return Value : u8
*   Calls        :
*   Called By    :
*****************************************************************************/
u8 nsfw_ps_reg_global_fun(u8 proc_type, u8 ps_state, nsfw_ps_proc_fun fun,
                          void *argv)
{
    if (NSFW_PROC_MAX <= proc_type)
    {
        NSFW_LOGERR("proc_type err]state=%u,fun=%p,type=%u", ps_state, fun,
                    proc_type);
        return FALSE;
    }

    nsfw_ps_callback *cb_fun = g_ps_init_callback[proc_type];
    u32 i;
    for (i = 0; i < NSFW_PS_MAX_CALLBACK; i++)
    {
        if (NULL == cb_fun[i].fun)
        {
            cb_fun[i].fun = fun;
            cb_fun[i].argv = argv;
            cb_fun[i].state = ps_state;
            NSFW_LOGINF("reg fun suc]type=%u,state=%u,fun=%p,argv=%p,i=%u",
                        proc_type, ps_state, fun, argv, i);
            return TRUE;
        }
    }

    NSFW_LOGERR("reg fun ful failed]type=%u,state=%u,fun=%p,argv=%p,i=%u",
                proc_type, ps_state, fun, argv, i);
    return FALSE;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_exit
*   Description  : when recvive the process exit finish message ,change
                   to exit state
*   Input        : nsfw_mgr_msg* msg
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nsfw_ps_exit(nsfw_mgr_msg * msg)
{
    nsfw_ps_info *pps_info;
    if (NULL == msg)
    {
        NSFW_LOGERR("msg nul!");
        return FALSE;
    }

    nsfw_ps_info_msg *ps_msg = GET_USER_MSG(nsfw_ps_info_msg, msg);
    pps_info = nsfw_ps_info_get(ps_msg->host_pid);
    NSFW_LOGINF("recv ps exit]host_pid=%u,ps_info=%p", ps_msg->host_pid,
                pps_info);

    if (NULL == pps_info)
    {
        NSFW_LOGERR("error msg pps_info nul]host_pid=%u", ps_msg->host_pid);
        return true;
    }
    (void) nsfw_sw_ps_state(pps_info, NSFW_PS_EXIT);
    return TRUE;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_info_fork_alloc
*   Description  : alloc fork ps_info
*   Input        : u32 parent_pid
*                  u32 child_pid
*   Output       : None
*   Return Value : nsfw_ps_info*
*   Calls        :
*   Called By    :
*****************************************************************************/
nsfw_ps_info *nsfw_ps_info_fork_alloc(u32 parent_pid, u32 child_pid)
{
    nsfw_ps_info *pps_info = NULL;
    nsfw_ps_info *pps_info_parent = NULL;
    pps_info_parent = nsfw_ps_info_get(parent_pid);
    if (NULL == pps_info_parent)
    {
        NSFW_LOGERR("pps_info_parent nul");
        return NULL;
    }

    pps_info = nsfw_ps_info_get(child_pid);
    if (NULL == pps_info)
    {
        pps_info =
            nsfw_ps_info_alloc(child_pid, pps_info_parent->proc_type, 0);
        if (NULL == pps_info)
        {
            NSFW_LOGERR
                ("alloc ps_info failed!]ps_info=%p,host_pid=%u,child_pid=%u",
                 pps_info_parent, pps_info_parent->host_pid, child_pid);
            return NULL;
        }
    }
    else
    {
        NSFW_LOGWAR
            ("fork alloc mem before!]ps_info=%p,host_pid=%u,child_pid=%u",
             pps_info_parent, pps_info_parent->host_pid, child_pid);
    }

    NSFW_LOGWAR("ps_info fork]ps_info=%p,host_pid=%u,child_pid=%u",
                pps_info_parent, pps_info_parent->host_pid, child_pid);
    pps_info->parent_pid = parent_pid;
    if (EOK !=
        memcpy_s(pps_info->callback, sizeof(pps_info->callback),
                 pps_info_parent->callback,
                 sizeof(pps_info_parent->callback)))
    {
        nsfw_ps_info_free(pps_info);
        NSFW_LOGERR("ps_info set_failed");
        return NULL;
    }

    if (EOK !=
        memcpy_s(pps_info->value, sizeof(pps_info->value),
                 pps_info_parent->value, sizeof(pps_info_parent->value)))
    {
        nsfw_ps_info_free(pps_info);
        NSFW_LOGERR("ps_info cpy_failed");
        return NULL;
    }

    return pps_info;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_info_alloc
*   Description  : alloc ps_info
*   Input        : u32 pid
*                  u8 proc_type
*   Output       : None
*   Return Value : nsfw_ps_info*
*   Calls        :
*   Called By    :
*****************************************************************************/
nsfw_ps_info *nsfw_ps_info_alloc(u32 pid, u8 proc_type, u8 realloc_flg)
{
    nsfw_ps_info *pps_info = NULL;
    if (0 == nsfw_mem_ring_dequeue(g_ps_cfg.ps_info_pool, (void *) &pps_info))
    {
        NSFW_LOGERR("alloc ps_info falied]pid=%u,type=%u", pid, proc_type);
        return NULL;
    }

    if (NULL == pps_info)
    {
        if (NSFW_PROC_MAIN != proc_type || TRUE == g_main_ps_info.alloc_flag)
        {
            NSFW_LOGERR("alloc ps_info nul]pid=%u,type=%u", pid, proc_type);
            return NULL;
        }
        pps_info = &g_main_ps_info;
    }

    if (EOK !=
        memset_s(pps_info, sizeof(nsfw_ps_info), 0, sizeof(nsfw_ps_info)))
    {
        NSFW_LOGERR("memset_s failed");
        goto error;
    }

    if (proc_type < NSFW_PROC_MAX)
    {
        int retval = memcpy_s(pps_info->callback, sizeof(pps_info->callback),
                              g_ps_init_callback[proc_type],
                              sizeof(pps_info->callback));
        if (EOK != retval)
        {
            NSFW_LOGERR("memcpy failed]retval=%d", retval);
            goto error;
        }
    }
    pps_info->proc_type = proc_type;
    pps_info->host_pid = pid;

    list_add_tail(&pps_info->node, &g_ps_runing_list);

    pps_info->alloc_flag = TRUE;
    (void) nsfw_sw_ps_state(pps_info, NSFW_PS_RUNNING);

    if (pid < NSFW_MAX_PID)
    {
        g_ps_info[pid].ps_info = pps_info;
        if (!realloc_flg)       /* If re-alloced, should keep the same as stored */
        {
            g_ps_info[pid].proc_type = proc_type;
            g_ps_info[pid].starttime =
                (u32) (nsfw_ps_get_starttime_from_file(pid) & 0xFFFFFFFF);
        }
    }

    NSFW_LOGINF("ps_info alloc]ps_info=%p,pid=%u,type=%u", pps_info, pid,
                proc_type);
    return pps_info;
  error:
    if (1 != nsfw_mem_ring_enqueue(g_ps_cfg.ps_info_pool, pps_info))
    {
        NSFW_LOGERR("nsfw_mem_ring_enqueue failed]ps_info=%p", pps_info);
    }
    return NULL;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_info_get
*   Description  : get ps_info by pid
*   Input        : u32 pid
*   Output       : None
*   Return Value : inline nsfw_ps_info*
*   Calls        :
*   Called By    :
*****************************************************************************/
inline nsfw_ps_info *nsfw_ps_info_get(u32 pid)
{
    if (pid < NSFW_MAX_PID)
    {
        return g_ps_info[pid].ps_info;
    }

    return NULL;
}

nsfw_ps_info *nsfw_share_ps_info_get(u32 pid)
{
    if (pid < NSFW_MAX_PID)
    {
        return g_master_ps_info[pid].ps_info;
    }

    return NULL;
}

void nsfw_ps_info_free(nsfw_ps_info * ps_info)
{
    if (NULL == ps_info)
    {
        NSFW_LOGERR("ps_info nul");
        return;
    }

    if (FALSE == ps_info->alloc_flag)
    {
        NSFW_LOGERR("ps_info refree]ps_info=%p,pid=%u,state=%u", ps_info,
                    ps_info->host_pid, ps_info->state);
        return;
    }

    if (NULL != ps_info->exit_timer_ptr)
    {
        nsfw_timer_rmv_timer((nsfw_timer_info *) ps_info->exit_timer_ptr);
        ps_info->exit_timer_ptr = NULL;
    }

    if (NULL != ps_info->resend_timer_ptr)
    {
        nsfw_timer_rmv_timer((nsfw_timer_info *) ps_info->resend_timer_ptr);
        ps_info->resend_timer_ptr = NULL;
    }

    if (NULL != ps_info->hbt_timer_ptr)
    {
        nsfw_timer_rmv_timer((nsfw_timer_info *) ps_info->hbt_timer_ptr);
        ps_info->hbt_timer_ptr = NULL;
    }

    list_del(&ps_info->node);

    ps_info->alloc_flag = FALSE;

    NSFW_LOGINF("ps_info free]ps_info=%p,pid=%u,state=%u", ps_info,
                ps_info->host_pid, ps_info->state);
    if (ps_info != &g_main_ps_info)
    {
        if (0 == nsfw_mem_ring_enqueue(g_ps_cfg.ps_info_pool, ps_info))
        {
            NSFW_LOGERR("ps_info free failed]ps_info=%p,pid=%u,state=%u",
                        ps_info, ps_info->host_pid, ps_info->state);
            return;
        }
    }

    if (ps_info->host_pid < NSFW_MAX_PID)
    {
        g_ps_info[ps_info->host_pid].proc_type = 0;
        g_ps_info[ps_info->host_pid].ps_info = NULL;
        g_ps_info[ps_info->host_pid].starttime = 0;
    }

    return;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_exiting_timeout
*   Description  : waiting for remove ps_info timeout
*   Input        : u32 timer_type
*                  void* data
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nsfw_ps_exiting_timeout(u32 timer_type, void *data)
{
    nsfw_ps_info *pps_info = (nsfw_ps_info *) data;

    if (NULL == pps_info)
    {
        return TRUE;
    }
    NSFW_LOGINF("ps_info timerout]pps_info=%p,pid=%u", pps_info,
                pps_info->host_pid);

    pps_info->exit_timer_ptr = NULL;

    if (TRUE == g_hbt_switch)
    {
        NSFW_LOGINF("hbt off");
        struct timespec time_left = { NSFW_PS_WEXIT_TVLAUE, 0 };
        pps_info->exit_timer_ptr =
            (void *) nsfw_timer_reg_timer(NSFW_PS_WEXIT_TIMER, pps_info,
                                          nsfw_ps_exiting_timeout, time_left);
        return TRUE;
    }

    if (NSFW_PS_EXITING == pps_info->state)
    {
        (void) nsfw_sw_ps_state(pps_info, NSFW_PS_EXIT);
    }

    return TRUE;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_exit_end_notify
*   Description  : send exitting state process finished
*   Input        : u32 pid
*   Output       : None
*   Return Value : u8
*   Calls        :
*   Called By    :
*****************************************************************************/
u8 nsfw_ps_exit_end_notify(u32 pid)
{
    nsfw_mgr_msg *rsp_msg =
        nsfw_mgr_msg_alloc(MGR_MSG_APP_EXIT_RSP, g_mgr_com_cfg.proc_type);
    if (NULL == rsp_msg)
    {
        NSFW_LOGERR("alloc rsp msg failed]pid=%u", pid);
        return FALSE;
    }

    nsfw_ps_info_msg *ps_msg = GET_USER_MSG(nsfw_ps_info_msg, rsp_msg);
    ps_msg->host_pid = pid;
    (void) nsfw_mgr_send_msg(rsp_msg);
    nsfw_mgr_msg_free(rsp_msg);
    NSFW_LOGINF("send exit rsp msg]pid=%u", pid);
    return TRUE;
}

/*****************************************************************************
*   Prototype    : nsfw_sw_ps_state
*   Description  : switch ps_info state
*   Input        : nsfw_ps_info* pps_info
*                  u8 new_state
*   Output       : None
*   Return Value : u8
*   Calls        :
*   Called By    :
*****************************************************************************/
u8 nsfw_sw_ps_state(nsfw_ps_info * pps_info, u8 new_state)
{
    if (NULL == pps_info)
    {
        NSFW_LOGERR("pps_info nul!");
        return FALSE;
    }

    u8 old_state = pps_info->state;
    NSFW_LOGINF("sw]ps_info=%p,pid=%u,type=%u,old_state=%u,newstate=%u",
                pps_info, pps_info->host_pid, pps_info->proc_type, old_state,
                new_state);

    if (NSFW_PS_HBT_FAILED != new_state)
    {
        pps_info->state = new_state;
    }

    i32 i, ret;
    for (i = 0; i < NSFW_PS_MAX_CALLBACK; i++)
    {
        if (NULL == pps_info->callback[i].fun)
        {
            /* NULL should be the last fun */
            break;
        }

        if (new_state == pps_info->callback[i].state)
        {
            ret =
                pps_info->callback[i].fun(pps_info,
                                          pps_info->callback[i].argv);
            NSFW_LOGINF("callback fun]ps_info=%p,i=%d,fun=%p,argv=%p,ret=%d",
                        pps_info, i, pps_info->callback[i].fun,
                        pps_info->callback[i].argv, ret);
        }
    }

    if (NSFW_PS_EXIT == new_state)
    {
        nsfw_ps_info_free(pps_info);
        if (NSFW_PS_EXITING == old_state)
        {
            dec_ps_exiting_cnt();
        }
    }

    if (NSFW_PS_EXITING == new_state)
    {
        struct timespec time_left = { NSFW_PS_WEXIT_TVLAUE, 0 };
        pps_info->exit_timer_ptr =
            (void *) nsfw_timer_reg_timer(NSFW_PS_WEXIT_TIMER, pps_info,
                                          nsfw_ps_exiting_timeout, time_left);
        inc_ps_exiting_cnt();
    }

    return TRUE;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_get_netlink_socket
*   Description  : get netlink socket to kernel
*   Input        : None
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 nsfw_ps_get_netlink_socket()
{
    int rc;
    int nl_sock;
    int size, size_len;
    struct sockaddr_nl sockad_nl;

    nl_sock = nsfw_base_socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nl_sock == -1)
    {
        NSFW_LOGERR("get netlink socket err]errno=%d", errno);
        return -1;
    }

    /* close on exec */
    rc = nsfw_set_close_on_exec(nl_sock);
    if (rc == -1)
    {
        (void) nsfw_base_close(nl_sock);
        NSFW_LOGERR("set exec err]fd=%d, errno=%d", nl_sock, errno);
        return -1;
    }

    sockad_nl.nl_family = AF_NETLINK;
    sockad_nl.nl_groups = CN_IDX_PROC;
    sockad_nl.nl_pid = getpid();

    rc = nsfw_base_bind(nl_sock, (struct sockaddr *) &sockad_nl,
                        sizeof(sockad_nl));
    if (rc == -1)
    {
        (void) nsfw_base_close(nl_sock);
        NSFW_LOGERR("netlink bind err]netlink_fd=%d, errno=%d", nl_sock,
                    errno);
        return -1;
    }

    /* this struct will be use */
    struct __attribute__ ((aligned(NLMSG_ALIGNTO)))
    {
        struct nlmsghdr nl_msg_hdr;
        struct __attribute__ ((__packed__))
        {
            struct cn_msg c_msg;
            enum proc_cn_mcast_op c_mcast;
        };
    } nlc_msg;

    if (EOK != memset_s(&nlc_msg, sizeof(nlc_msg), 0, sizeof(nlc_msg)))
    {
        (void) nsfw_base_close(nl_sock);
        NSFW_LOGERR("netlink set failed]netlink_fd=%d", nl_sock);
        return -1;
    }
    nlc_msg.nl_msg_hdr.nlmsg_len = sizeof(nlc_msg);
    nlc_msg.nl_msg_hdr.nlmsg_pid = getpid();
    nlc_msg.nl_msg_hdr.nlmsg_type = NLMSG_DONE;

    nlc_msg.c_msg.id.idx = CN_IDX_PROC;
    nlc_msg.c_msg.id.val = CN_VAL_PROC;
    nlc_msg.c_msg.len = sizeof(enum proc_cn_mcast_op);

    nlc_msg.c_mcast = PROC_CN_MCAST_LISTEN;
    rc = nsfw_base_send(nl_sock, &nlc_msg, sizeof(nlc_msg), 0);
    if (rc == -1)
    {
        (void) nsfw_base_close(nl_sock);
        NSFW_LOGERR("netlink send err]netlink_fd=%d, errno=%d", nl_sock,
                    errno);
        return -1;
    }

    NSFW_LOGINF("netlink connect]netlink_fd=%d", nl_sock);

    int val = 0;
    int len = sizeof(val);
    if (0 >
        nsfw_base_getsockopt(nl_sock, SOL_SOCKET, SO_RCVBUF, &val,
                             (socklen_t *) & len))
    {
        NSFW_LOGERR("get socket opt err]error=%d", errno);
    }
    else
    {
        NSFW_LOGINF("]SO_RCVBUF=0x%x", val);
    }

    size = MAX_NET_LINK_BUF;
    size_len = sizeof(size);
    if (0 >
        nsfw_base_setsockopt(nl_sock, SOL_SOCKET, SO_RCVBUFFORCE,
                             (void *) &size, (socklen_t) size_len))
    {
        NSFW_LOGERR("set socket opt err]error=%d", errno);
    }

    size_len = sizeof(size);
    if (0 >
        nsfw_base_getsockopt(nl_sock, SOL_SOCKET, SO_RCVBUF, (void *) &size,
                             (socklen_t *) & size_len))
    {
        NSFW_LOGERR("get socket opt err]error=%d", errno);
    }

    NSFW_LOGINF("]SO_RCVBUF=0x%x", size);
    return nl_sock;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_change_fun
*   Description  : proc change when receive event from kernel
*   Input        : i32 epfd
*                  i32 fd
*                  u32 events
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nsfw_ps_change_fun(i32 epfd, i32 fd, u32 events)
{
    i32 rc;
    u32 host_pid;
    nsfw_ps_info *pps_info = NULL;

    /*this struct will be used */
    struct __attribute__ ((aligned(NLMSG_ALIGNTO)))
    {
        struct nlmsghdr nl_msg_hdr;
        struct __attribute__ ((__packed__))
        {
            struct cn_msg c_msg;
            struct proc_event p_ev;
        };
    } nlc_msg;

    if (!(events & EPOLLIN))
    {
        return TRUE;
    }

    while (1)
    {
        rc = nsfw_base_recv(fd, &nlc_msg, sizeof(nlc_msg), 0);
        if (rc == 0)
        {
            NSFW_LOGWAR("netlink recv 0]netlink_fd=%d,errno=%d", fd, errno);
            break;
        }
        else if (rc == -1)
        {
            if (errno == EINTR || errno == EAGAIN)
            {
                break;
            }
            NSMON_LOGERR("netlink recv]netlink_fd=%d,errno=%d", fd, errno);
            if (errno == ENOBUFS)
            {
                struct timespec time_left = { NSFW_PS_FIRST_CHK_TVLAUE, 0 };
                g_ps_chk_timer =
                    (void *) nsfw_timer_reg_timer(NSFW_PS_CHK_TIMER,
                                                  (void *) FALSE,
                                                  nsfw_ps_chk_timeout,
                                                  time_left);
            }
            break;
        }

        switch (nlc_msg.p_ev.what)
        {
            case PROC_EVENT_EXIT:      /*enum or int no effect here */
                host_pid = nlc_msg.p_ev.event_data.exit.process_pid;
                pps_info = nsfw_ps_info_get(host_pid);
                if (NULL == pps_info)
                {
                    /*too many useless debug log, del NSFW_LOGDBG("pps info is null]host pid=%u", host_pid); */
                    break;
                }

                if (NSFW_PS_EXITING == pps_info->state)
                {
                    NSFW_LOGERR("double pid info]ps_info=%p,pid=%u",
                                pps_info, host_pid);
                    break;
                }

                (void) nsfw_sw_ps_state(pps_info, NSFW_PS_EXITING);
                break;
            default:
                break;
        }
    }

    return TRUE;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_start_netlink
*   Description  : reg ps_module to epoll thread
*   Input        : None
*   Output       : None
*   Return Value : u8
*   Calls        :
*   Called By    :
*****************************************************************************/
u8 nsfw_ps_start_netlink()
{

    i32 netlink_fd = nsfw_ps_get_netlink_socket();
    if (netlink_fd < 0)
    {
        NSFW_LOGERR("get netlink failed!");
        return FALSE;
    }

    NSFW_LOGINF("start ps_info module!]netlink_fd=%d", netlink_fd);
    (void) nsfw_mgr_reg_sock_fun(netlink_fd, nsfw_ps_change_fun);
    (void) nsfw_mgr_reg_msg_fun(MGR_MSG_APP_EXIT_RSP, nsfw_ps_exit);
    return TRUE;
}

/* for heartbeat check*/

NSTACK_STATIC __thread i32 t_val_idx = 0;
nsfw_thread_dogs g_thread_dogs[NSFW_MAX_THREAD_DOGS_COUNT];
/*****************************************************************************
*   Prototype    : nsfw_all_thread_chk
*   Description  : get all thread check state
*   Input        : None
*   Output       : None
*   Return Value : i32
*   Calls        :
*   Called By    :
*****************************************************************************/
i32 nsfw_all_thread_chk()
{
    i32 count = -1;
    u32 i;
    for (i = 0; i < NSFW_MAX_THREAD_DOGS_COUNT; i++)
    {
        if (FALSE == g_thread_dogs[i].alloc_flag)
        {
            continue;
        }

        if (count < g_thread_dogs[i].count)
        {
            count = g_thread_dogs[i].count;
        }

        /* only if the thread abnormal, then output log */
        if (g_thread_dogs[i].count > 0)
        {                       /* print thread_id, know which thread is abnormal */
            NSFW_LOGINF("hb_timeout]count=%d,thread_id=%u",
                        g_thread_dogs[i].count, g_thread_dogs[i].thread_id);
        }

        g_thread_dogs[i].count++;
    }
    return count;
}

/*****************************************************************************
*   Prototype    : nsfw_thread_chk_unreg
*   Description  : cancel the thread check
*   Input        : None
*   Output       : None
*   Return Value : inline u8
*   Calls        :
*   Called By    :
*****************************************************************************/
inline u8 nsfw_thread_chk_unreg()
{
    if (t_val_idx > 0 && t_val_idx < NSFW_MAX_THREAD_DOGS_COUNT)
    {
        g_thread_dogs[t_val_idx].alloc_flag = FALSE;
        g_thread_dogs[t_val_idx].count = 0;
        g_thread_dogs[t_val_idx].thread_id = 0;
        t_val_idx = 0;
    }
    return TRUE;
}

/*****************************************************************************
*   Prototype    : nsfw_thread_chk
*   Description  : add the thread to check, and should be call in every
                   process cycle
*   Input        : None
*   Output       : None
*   Return Value : inline u8
*   Calls        :
*   Called By    :
*****************************************************************************/
inline u8 nsfw_thread_chk()
{
    u32 i;
    if (t_val_idx > 0 && t_val_idx < NSFW_MAX_THREAD_DOGS_COUNT)
    {
        g_thread_dogs[t_val_idx].count = 0;
        return TRUE;
    }

    for (i = 1; i < NSFW_MAX_THREAD_DOGS_COUNT; i++)
    {
        /*
           (1) use some fixed value but no effect  (e506)
           (2) it don't contain any extra commas (e505)
         */
        if ((FALSE == g_thread_dogs[i].alloc_flag)
            && __sync_bool_compare_and_swap(&g_thread_dogs[i].alloc_flag,
                                            FALSE, TRUE))
        {
            t_val_idx = i;
            break;
        }
    }

    if (t_val_idx > 0 && t_val_idx < NSFW_MAX_THREAD_DOGS_COUNT)
    {
        g_thread_dogs[t_val_idx].count = 0;
        g_thread_dogs[t_val_idx].thread_id = syscall(SYS_gettid);
    }

    return TRUE;
}

nsfw_thread_dogs *nsfw_thread_get_dog()
{
    u32 i;
    nsfw_thread_dogs *retPtr = NULL;
    if (t_val_idx > 0 && t_val_idx < NSFW_MAX_THREAD_DOGS_COUNT)
    {
        return &g_thread_dogs[t_val_idx];
    }

    for (i = 1; i < NSFW_MAX_THREAD_DOGS_COUNT; i++)
    {
        /*
           (1) use some fixed value but no effect  (e506)
           (2) it don't contain any extra commas (e505)
         */
        if ((FALSE == g_thread_dogs[i].alloc_flag)
            && __sync_bool_compare_and_swap(&g_thread_dogs[i].alloc_flag,
                                            FALSE, TRUE))
        {
            t_val_idx = i;
            break;
        }
    }

    if (t_val_idx > 0 && t_val_idx < NSFW_MAX_THREAD_DOGS_COUNT)
    {
        g_thread_dogs[t_val_idx].count = 0;
        g_thread_dogs[t_val_idx].thread_id = syscall(SYS_gettid);
        retPtr = &g_thread_dogs[t_val_idx];
    }
    return retPtr;
}

pthread_t g_all_thread[MAX_THREAD] = { 0 };

u8 nsfw_reg_trace_thread(pthread_t tid)
{
    int i;
    for (i = 0; i < MAX_THREAD; i++)
    {
        if ((0 == g_all_thread[i])
            && __sync_bool_compare_and_swap(&g_all_thread[i], 0, tid))
        {
            return TRUE;
        }
    }
    return FALSE;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_check_dst_init
*   Description  : send check msg check the dst process is listening
*   Input        : u8 dst_proc_type
*   Output       : None
*   Return Value : u8
*   Calls        :
*   Called By    :
*****************************************************************************/
u8 nsfw_ps_check_dst_init(u8 dst_proc_type)
{
    u8 ps_state = FALSE;
    nsfw_mgr_msg *msg =
        nsfw_mgr_msg_alloc(MGR_MSG_CHK_INIT_REQ, dst_proc_type);
    if (NULL == msg)
    {
        NSFW_LOGERR("alloc msg failed]dst_typ=%d", dst_proc_type);
        return FALSE;
    }

    nsfw_ps_chk_msg *ps_msg = GET_USER_MSG(nsfw_ps_chk_msg, msg);
    ps_msg->ps_state = TRUE;

    nsfw_mgr_msg *rsp_msg = nsfw_mgr_null_rspmsg_alloc();
    if (NULL == rsp_msg)
    {
        nsfw_mgr_msg_free(msg);
        NSFW_LOGERR("alloc rsp msg failed]dst_typ=%d", dst_proc_type);
        return FALSE;
    }

    (void) nsfw_mgr_send_req_wait_rsp(msg, rsp_msg);

    ps_msg = GET_USER_MSG(nsfw_ps_chk_msg, rsp_msg);
    ps_state = ps_msg->ps_state;

    nsfw_mgr_msg_free(msg);
    nsfw_mgr_msg_free(rsp_msg);
    NSFW_LOGINF("get peer state]dst_type=%d,state=%d", dst_proc_type,
                ps_state);
    return ps_state;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_send_hbt
*   Description  : seng heart beat message to peer
*   Input        : nsfw_ps_info* pps_info
*   Output       : None
*   Return Value : u8
*   Calls        :
*   Called By    :
*****************************************************************************/
u8 nsfw_ps_send_hbt(nsfw_ps_info * pps_info)
{
    if (NULL == pps_info)
    {
        NSFW_LOGERR("null ps_info!");
        return FALSE;
    }

    nsfw_mgr_msg *req_msg =
        nsfw_mgr_msg_alloc(MGR_MSG_CHK_HBT_REQ, pps_info->proc_type);
    if (NULL == req_msg)
    {
        NSFW_LOGERR("alloc req msg failed]pps_info=%p", pps_info);
        return FALSE;
    }

    req_msg->dst_pid = pps_info->host_pid;
    nsfw_ps_chk_msg *ps_msg = GET_USER_MSG(nsfw_ps_chk_msg, req_msg);
    ps_msg->ps_state = TRUE;
    u8 ret = nsfw_mgr_send_msg(req_msg);
    nsfw_mgr_msg_free(req_msg);
    NSFW_LOGDBG("send hbt msg]ret=%d,pps_info=%p,pid=%u,type=%d", ret,
                pps_info, pps_info->host_pid, pps_info->proc_type);
    return ret;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_recv_hbt
*   Description  : recv heart beat message process
*   Input        : nsfw_mgr_msg* msg
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nsfw_ps_recv_hbt(nsfw_mgr_msg * msg)
{
    if (NULL == msg)
    {
        NSFW_LOGERR("error msg nul!");
        return FALSE;
    }

    nsfw_mgr_msg *rsp_msg = nsfw_mgr_rsp_msg_alloc(msg);
    if (NULL == rsp_msg)
    {
        NSFW_LOGERR("alloc rsp failed,drop msg!" MSGINFO, PRTMSG(msg));
        return FALSE;
    }

    nsfw_ps_chk_msg *ps_msg = GET_USER_MSG(nsfw_ps_chk_msg, rsp_msg);
    ps_msg->ps_state = TRUE;
    ps_msg->thread_chk_count = nsfw_all_thread_chk();
    (void) nsfw_mgr_send_msg(rsp_msg);
    nsfw_mgr_msg_free(rsp_msg);

    return TRUE;
}

void log_sys_process_info(void)
{
    /* get thread info which is running in 0 core cpu */
#define GET_SYS_PROCESS_STATUS_INFO "ps c -w  -T -e -O user,s,spid,%cpu,%mem,psr,start  --sort -pcpu |grep -E 'PSR| R ' |grep -E 'PSR| 0 | 1 '"
    /* check cpu usage of all thread for daemon-stack process, this cmd running need spend 180ms */
#define GET_NSTACK_MAIN_PROCESS_STATUS_INFO "top -d 1  -H -p `pidof nStackMain` -n 1 -b"
    char result[SPL_MAX_BUF_LEN] = { 0 };
    int retVal =
        nsfw_mgr_run_script(GET_NSTACK_MAIN_PROCESS_STATUS_INFO, result,
                            SPL_MAX_BUF_LEN);
    if (-1 != retVal)
    {
        NSFW_LOGWAR("NSTACK_MAIN=%d\n%s", retVal, result);
    }
    retVal =
        nsfw_mgr_run_script(GET_SYS_PROCESS_STATUS_INFO, result,
                            SPL_MAX_BUF_LEN);
    if (-1 != retVal)
    {
        NSFW_LOGWAR("SYS=%d\n%s", retVal, result);
    }
}

/*****************************************************************************
*   Prototype    : nsfw_ps_recv_hbt_rsp
*   Description  : recv heart beat response message process
*   Input        : nsfw_mgr_msg* msg
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nsfw_ps_recv_hbt_rsp(nsfw_mgr_msg * msg)
{
    if (NULL == msg)
    {
        NSFW_LOGERR("error msg nul!");
        return FALSE;
    }

    nsfw_ps_chk_msg *ps_msg = GET_USER_MSG(nsfw_ps_chk_msg, msg);
    if (TRUE != ps_msg->ps_state)
    {
        NSFW_LOGERR("Heartbeat failed]pid=%u,type=%u", msg->src_pid,
                    msg->src_proc_type);
        return FALSE;
    }

    nsfw_ps_info *pps_info = nsfw_ps_info_get(msg->src_pid);
    if (NULL == pps_info)
    {
        NSFW_LOGERR("get ps_info failed]pid=%u,type=%u,count=%d",
                    msg->src_pid, msg->src_proc_type,
                    ps_msg->thread_chk_count);
        return FALSE;
    }

    if (0 == ps_msg->thread_chk_count)
    {
        pps_info->hbt_failed_count = 0;

        /* send daemon-stack normal alarm, when hb normal one time */
        omc_send_nsmain_alarm(ALARM_EVENT_NSTACK_MAIN_ABNORMAL_RESTART_FAIL,
                              ALARM_CLEAN);
        return TRUE;
    }

    u32 tmp_hbt_failed_count = pps_info->hbt_failed_count;

    if (pps_info->hbt_failed_count > (u32) ps_msg->thread_chk_count)
    {
        pps_info->hbt_failed_count = (u32) ps_msg->thread_chk_count;
    }

    NSFW_LOGERR("Heartbeat failed]pid=%u,type=%u,count=%d,ps_count=%u",
                msg->src_pid, msg->src_proc_type, ps_msg->thread_chk_count,
                pps_info->hbt_failed_count);
    /* for fast get sys process status info */
    if (1 == tmp_hbt_failed_count)
    {
        log_sys_process_info();
    }
    return FALSE;
}

int nsfw_ps_reset_hbt(void *pps_info, void *argv)
{
    nsfw_ps_info *ps_info = pps_info;
    if (NULL == ps_info)
    {
        NSFW_LOGERR("ps_info nul!");
        return FALSE;
    }

    if (NSFW_PROC_MAIN != ps_info->proc_type)
    {
        return FALSE;
    }

    ps_info->hbt_failed_count = *(u32 *) argv;
    return TRUE;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_hbt_timeout
*   Description  : heart beat time out
*   Input        : u32 timer_type
*                  void* data
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nsfw_ps_hbt_timeout(u32 timer_type, void *data)
{
    nsfw_ps_info *pps_info = (nsfw_ps_info *) data;

    if (NULL == pps_info)
    {
        NSFW_LOGERR("null ps_info!");
        return FALSE;
    }

    if (NULL == pps_info->hbt_timer_ptr)
    {
        NSFW_LOGERR("hbt has stop]pps_info=%p", pps_info);
        pps_info->hbt_failed_count = 0;
        return TRUE;
    }

    if (TRUE == g_hbt_switch)
    {
        struct timespec time_left = { NSFW_CHK_HBT_TVLAUE, 0 };
        pps_info->hbt_timer_ptr =
            (void *) nsfw_timer_reg_timer(NSFW_CHK_HBT_TIMER, data,
                                          nsfw_ps_hbt_timeout, time_left);
        return TRUE;
    }

    /* nic init may cost a few seconds, master will restart main if heartbeat timeout- Begin */
    if (NSFW_SOFT_HBT_CHK_COUNT != NSFW_MAX_HBT_CHK_COUNT)
    {
        if (NSFW_SOFT_HBT_CHK_COUNT < NSFW_MAX_HBT_CHK_COUNT)
        {
            u32 new_hbt_count = 0;
            (void) nsfw_ps_iterator(nsfw_ps_reset_hbt, &new_hbt_count);
        }

        NSFW_MAX_HBT_CHK_COUNT = NSFW_SOFT_HBT_CHK_COUNT;
    }

    if (NSFW_MAX_HBT_CHK_COUNT <= pps_info->hbt_failed_count)
    {
        (void) nsfw_sw_ps_state(pps_info, NSFW_PS_HBT_FAILED);
        /*reset counter */
        pps_info->hbt_failed_count = 0;
    }

    if (TRUE != nsfw_ps_send_hbt(pps_info))
    {
    }

    struct timespec time_left = { NSFW_CHK_HBT_TVLAUE, 0 };
    pps_info->hbt_timer_ptr =
        (void *) nsfw_timer_reg_timer(NSFW_CHK_HBT_TIMER, data,
                                      nsfw_ps_hbt_timeout, time_left);

    if (pps_info->hbt_failed_count > 0)
    {
        NSFW_LOGWAR("Heartbeat failed]pid=%u,ps_count=%u, max_count=%d",
                    pps_info->host_pid, pps_info->hbt_failed_count,
                    NSFW_MAX_HBT_CHK_COUNT);
        log_sys_process_info();
    }

    pps_info->hbt_failed_count++;
    return TRUE;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_hbt_start
*   Description  : start ps_info heart beat
*   Input        : nsfw_ps_info* pps_info
*   Output       : None
*   Return Value : u8
*   Calls        :
*   Called By    :
*****************************************************************************/
u8 nsfw_ps_hbt_start(nsfw_ps_info * pps_info)
{
    if (NULL == pps_info)
    {
        NSFW_LOGERR("null ps_info");
        return FALSE;
    }

    if (NULL != pps_info->hbt_timer_ptr)
    {
        NSFW_LOGERR("hbt start before]ps_info=%p,pid=%u,type=%u", pps_info,
                    pps_info->host_pid, pps_info->proc_type);
        return FALSE;
    }

    struct timespec time_left = { NSFW_CHK_HBT_TVLAUE, 0 };
    pps_info->hbt_timer_ptr =
        (void *) nsfw_timer_reg_timer(NSFW_CHK_HBT_TIMER, (void *) pps_info,
                                      nsfw_ps_hbt_timeout, time_left);
    NSFW_LOGINF("hbt start]ps_info=%p,pid=%u,type=%u", pps_info,
                pps_info->host_pid, pps_info->proc_type);
    return TRUE;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_hbt_stop
*   Description  : stop ps_info heart beat
*   Input        : nsfw_ps_info* pps_info
*   Output       : None
*   Return Value : u8
*   Calls        :
*   Called By    :
*****************************************************************************/
u8 nsfw_ps_hbt_stop(nsfw_ps_info * pps_info)
{
    if (NULL == pps_info)
    {
        NSFW_LOGERR("null ps_info!");
        return FALSE;
    }

    if (NULL != pps_info->hbt_timer_ptr)
    {
        nsfw_timer_rmv_timer((nsfw_timer_info *) pps_info->hbt_timer_ptr);
        pps_info->hbt_timer_ptr = NULL;
    }

    NSFW_LOGINF("hbt stop!]ps_info=%p,pid=%u,type=%d", pps_info,
                pps_info->host_pid, pps_info->proc_type);
    return TRUE;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_iterator
*   Description  : get all ps_info process by fun
*   Input        : nsfw_ps_proc_fun fun
*                  void* argv
*   Output       : None
*   Return Value : u32
*   Calls        :
*   Called By    :
*****************************************************************************/
u32 nsfw_ps_iterator(nsfw_ps_proc_fun fun, void *argv)
{
    u32 count = 0;
    nsfw_ps_info *pps_info = NULL;
    struct list_head *tNode;

    if (NULL == fun)
    {
        NSFW_LOGERR("fun null!");
        return count;
    }

    list_for_each_entry(pps_info, tNode, (&g_ps_runing_list), node)
    {
        (void) fun(pps_info, argv);
        count++;
    }

    NSFW_LOGINF("proc pid]count=%u", count);
    return count;
}

int filter(const struct dirent *dir)
{
    return !fnmatch("[1-9]*", dir->d_name, 0);
}

/*****************************************************************************
*   Prototype    : nsfw_ps_realloc_pid
*   Description  : realloc pid
*   Input        : u32 pid
*   Output       : None
*   Return Value : inline nsfw_ps_info*
*   Calls        :
*   Called By    :
*****************************************************************************/
inline nsfw_ps_info *nsfw_ps_realloc_pid(u32 pid, u8 realloc_flg)
{
    nsfw_ps_info *pps_info = NULL;
    if (pid >= NSFW_MAX_PID)
    {
        return NULL;
    }

    if (g_ps_info[pid].ps_info == NULL)
    {
        return NULL;
    }

    if (TRUE == realloc_flg)
    {
        pps_info = nsfw_ps_info_alloc(pid, g_ps_info[pid].proc_type, 1);
        if (NULL == pps_info)
        {
            NSFW_LOGERR("alloc ps_info failed!]pid=%u,type=%u", pid,
                        g_ps_info[pid].proc_type);
            return NULL;
        }
    }
    else
    {
        pps_info = g_ps_info[pid].ps_info;
    }

    pps_info->rechk_flg = TRUE;
    return pps_info;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_reload_pid
*   Description  : reload pid
*   Input        : None
*   Output       : None
*   Return Value : void
*   Calls        :
*   Called By    :
*****************************************************************************/
void nsfw_ps_reload_pid()
{
    struct dirent **namelist;
    i32 n;
    u32 host_pid;
    nsfw_ps_info *pps_info = NULL;

    n = scandir("/proc", &namelist, filter, 0);
    if (n < 0)
    {
        NSFW_LOGERR("buf null");
    }
    else
    {

        while (n--)
        {
            host_pid = strtol(namelist[n]->d_name, NULL, 10);
            pps_info = nsfw_ps_info_get(host_pid);
            if ((NULL != pps_info) &&   /* There is a nStack app with this pid, and */
                (nsfw_ps_get_starttime_from_file(host_pid) == nsfw_ps_get_starttime_from_info(host_pid) /* starttime is the same */
                 || 0 == nsfw_ps_get_starttime_from_info(host_pid))     /* or NA in earlier version of Master */
                )
            {
                pps_info->rechk_flg = FALSE;
            }
            free(namelist[n]);
        }
        free(namelist);
    }
    return;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_realloc_all_pid
*   Description  : realloc all pid
*   Input        : u32 *main_pid
*   Output       : None
*   Return Value : void
*   Calls        :
*   Called By    :
*****************************************************************************/
void nsfw_ps_realloc_all_pid(u32 * main_pid, u8 realloc_flg)
{
    u32 i;
    nsfw_ps_info *pps_info = NULL;
    for (i = 0; i < NSFW_MAX_PID; i++)
    {
        pps_info = nsfw_ps_realloc_pid(i, realloc_flg);
        if (NULL != main_pid)
        {
            if (NULL != pps_info && NSFW_PROC_MAIN == pps_info->proc_type)
            {
                (*main_pid) = i;
            }
        }
    }
}

/*****************************************************************************
*   Prototype    : nsfw_ps_chk_exit_timeout
*   Description  : chk ps info
*   Input        : u32 timer_type
*                  void* data
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nsfw_ps_chk_exit_timeout(u32 timer_type, void *data)
{
    u32 i;
    nsfw_ps_info *pps_info = NULL;
    u32 pid = (u64) data;

    /*main pid exit first */
    if (NULL != data)
    {
        pps_info = nsfw_ps_info_get(pid);
        if (NULL != pps_info && TRUE == pps_info->rechk_flg)
        {
            if (NSFW_PS_EXITING != pps_info->state)
            {
                NSFW_LOGWAR("rechk pid exit]ps_info=%p,pid=%u", pps_info,
                            pps_info->host_pid);
                (void) nsfw_sw_ps_state(pps_info, NSFW_PS_EXITING);
                pps_info->rechk_flg = FALSE;
            }
        }
    }

    for (i = 0; i < NSFW_MAX_PID; i++)
    {
        pps_info = nsfw_ps_info_get(i);
        if (NULL != pps_info && TRUE == pps_info->rechk_flg)
        {
            if (NSFW_PS_EXITING == pps_info->state)
            {
                NSFW_LOGWAR("double pid info]ps_info=%p,pid=%u", pps_info,
                            pps_info->host_pid);
                continue;
            }

            NSFW_LOGWAR("rechk pid exit]ps_info=%p,pid=%u", pps_info,
                        pps_info->host_pid);
            (void) nsfw_sw_ps_state(pps_info, NSFW_PS_EXITING);
            pps_info->rechk_flg = FALSE;
        }
    }

    return TRUE;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_chk_timeout
*   Description  : load all running pid
*   Input        : u32 timer_type
*                  void* data
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nsfw_ps_chk_timeout(u32 timer_type, void *data)
{
    u32 main_pid = 0;
    u8 realloc_flg = (u8) (u64) data;

    nsfw_ps_realloc_all_pid(&main_pid, realloc_flg);
    nsfw_ps_reload_pid();

    struct timespec time_left = { NSFW_PS_CHK_EXIT_TVLAUE, 0 };
    g_ps_chk_timer =
        (void *) nsfw_timer_reg_timer(NSFW_PS_CHK_EXIT_TVLAUE,
                                      (void *) (u64) main_pid,
                                      nsfw_ps_chk_exit_timeout, time_left);
    return TRUE;
}

int nsfw_ps_check_pid_nstack_status(int pid)
{

    if (pid < 0 || pid >= NSFW_MAX_PID)
    {
        NSFW_LOGWAR("get wrong pid :%d", pid);
        return -1;
    }

    if (NULL == g_master_ps_info[pid].ps_info)
    {
        return -1;
    }

    /* pid is using nstack */
    return 0;
}

/*****************************************************************************
*   Prototype    : nsfw_ps_rechk_pid_exit
*   Description  : rechck pid exit
*   Input        : nsfw_ps_proc_fun fun
*                  void* argv
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nsfw_ps_rechk_pid_exit(nsfw_ps_pid_fun fun, void *argv)
{

    u32 ulI = 0;
    if (NULL == fun)
    {
        NSFW_LOGERR("input err! fun null");
        return -1;
    }

    u8 *ps_pid = malloc(NSFW_MAX_PID);
    if (NULL == ps_pid)
    {
        NSFW_LOGERR("malloc failed");
        return -1;
    }

    int retval = memset_s(ps_pid, NSFW_MAX_PID, 0, NSFW_MAX_PID);
    if (EOK != retval)
    {
        NSFW_LOGERR("memset_s failed]retval=%d", retval);
        free(ps_pid);
        return -1;
    }

    struct dirent **namelist;
    i32 n;
    u32 host_pid;
    n = scandir("/proc", &namelist, filter, 0);
    if (n < 0)
    {
        NSFW_LOGERR("buf null");
        free(ps_pid);
        return -1;
    }

    while (n--)
    {
        host_pid = strtol(namelist[n]->d_name, NULL, 10);
        /* here should use host_pid as ps_pid's index */
        if (host_pid < NSFW_MAX_PID)
        {
            ps_pid[host_pid] = TRUE;
        }
        free(namelist[n]);
        namelist[n] = NULL;
    }
    free(namelist);

    int count = 0;
    for (ulI = 0; ulI < NSFW_MAX_PID; ulI++)
    {
        if ((NULL != g_master_ps_info[ulI].ps_info) && (FALSE == ps_pid[ulI]))
        {
            (void) fun(ulI, g_master_ps_info[ulI].proc_type, argv);
            NSFW_LOGWAR("rechk pid exit]ulI=%u,type=%d", ulI,
                        g_master_ps_info[ulI].proc_type);
            count++;
            continue;
        }
    }

    free(ps_pid);
    return count;
}

void nsfw_ps_cfg_set_chk_count(u16 count)
{
    g_ps_cfg.ps_chk_hbt_count = count;
}

u64 nsfw_ps_get_starttime_from_file(u32 pid)
{
    if (pid > NSFW_MAX_PID)
    {
        NSFW_LOGERR("Invalid pid=%u", pid);
        return 0;
    }

    char str[20];
    if (sprintf_s(str, sizeof(str), "/proc/%u/stat", pid) < 0)
    {
        NSFW_LOGERR("sprintf_s failed, pid=%u", pid);
        return 0;
    }

    FILE *psfile = fopen(str, "r");
    if (NULL == psfile)
    {
        NSFW_LOGERR("fopen /proc/%u/stat failed", pid);
        return 0;
    }

    u64 starttime = 0;
    const char PROC_PID_STAT_FORMAT_GET_STARTTIME_ONLY[] = "%*d "       /* 1. pid */
        "%*s "                  /* 2. filename of exe */
        "%*c "                  /* 3. state */
        "%*d "                  /* 4. ppid */
        "%*d "                  /* 5. process group */
        "%*d "                  /* 6. session ID */
        "%*d "                  /* 7. tty_nr */
        "%*d "                  /* 8. tpgid */
        "%*u "                  /* 9. flags */
        "%*u "                  /* 10. minflt */
        "%*u "                  /* 11. cminflt */
        "%*u "                  /* 12. majflt */
        "%*u "                  /* 13. cmajflt */
        "%*u "                  /* 14. utime */
        "%*u "                  /* 15. stime */
        "%*d "                  /* 16. cuttime */
        "%*d "                  /* 17. cstime */
        "%*d "                  /* 18. priority */
        "%*d "                  /* 19. nice */
        "%*d "                  /* 20. num_threads */
        "%*d "                  /* 21. NA since Linux 2.6 */
        "%llu";                 /* 22. starttime, we need this field */

    int ret;
    if ((ret =
         fscanf_s(psfile, PROC_PID_STAT_FORMAT_GET_STARTTIME_ONLY,
                  &starttime)) != 1)
    {
        NSFW_LOGERR("fscanf_s /proc/%u/stat failed, ret=%d, errno=%d", pid,
                    ret, errno);
        fclose(psfile);         /*no need to check return */
        return 0;
    }

    NSFW_LOGDBG("pid:%u, starttime:%llu", pid, starttime);
    fclose(psfile);             /*no need to check return */
    return starttime;
}

u64 nsfw_ps_get_starttime_from_info(u32 pid)
{
    return (u64) (g_ps_info[pid].starttime);
}

int nsfw_ps_module_init(void *param)
{
    u32 proc_type = (u32) ((long long) param);
    nsfw_ps_init_cfg *ps_cfg = &g_ps_cfg;
    int retval;
    nsfw_pid_item *pid_info = NULL;
    enum_alarm_id loop_alarm_id = ALARM_EVENT_BASE;

    NSFW_LOGINF("ps module init]type=%u", proc_type);

    ps_cfg->ps_chk_hbt_count = NSFW_MAX_HBT_CHK_COUNT_DEF;
    ps_cfg->ps_chk_hbt_tvalue = NSFW_CHK_HBT_TVLAUE_DEF;
    ps_cfg->ps_chk_hbt_soft_count = ps_cfg->ps_chk_hbt_count;

    nsfw_mem_zone pzoneinfo;
    pzoneinfo.isocket_id = NSFW_SOCKET_ANY;
    pzoneinfo.stname.entype = NSFW_SHMEM;
    pzoneinfo.lenth = sizeof(nsfw_pid_item) * NSFW_MAX_PID;
    if (-1 ==
        sprintf_s(pzoneinfo.stname.aname, NSFW_MEM_NAME_LENTH, "%s",
                  "MAS_PS_INFO"))
    {
        NSFW_LOGERR("sprintf_s failed]");
        return -1;
    }

    switch (proc_type)
    {
        case NSFW_PROC_MASTER:
            {
                (void) nsfw_mgr_reg_msg_fun(MGR_MSG_CHK_HBT_RSP,
                                            nsfw_ps_recv_hbt_rsp);
                (void) nsfw_mgr_reg_msg_fun(MGR_MSG_CHK_INIT_REQ,
                                            nsfw_ps_recv_hbt);
                (void) nsfw_mgr_reg_msg_fun(MGR_MSG_CHK_HBT_REQ,
                                            nsfw_ps_recv_hbt);
                (void) NSFW_REG_SOFT_INT(NSFW_HBT_TIMER, NSFW_CHK_HBT_TVLAUE,
                                         1, 0xFFFF);
                (void) NSFW_REG_SOFT_INT(NSFW_HBT_COUNT_PARAM,
                                         NSFW_SOFT_HBT_CHK_COUNT, 1, 0xFFFF);
                (void) NSFW_REG_SOFT_INT(NSFW_APP_EXIT_TIMER,
                                         NSFW_PS_WEXIT_TVLAUE, 1, 0xFFFF);

                pid_info = nsfw_mem_zone_lookup(&pzoneinfo.stname);
                if (NULL == pid_info)
                {
                    pid_info = nsfw_mem_zone_create(&pzoneinfo);
                    if (NULL == pid_info)
                    {
                        NSFW_LOGERR("alloc rec nul!");
                        return -1;
                    }

                    retval =
                        memset_s(pid_info,
                                 (sizeof(nsfw_pid_item) * NSFW_MAX_PID), 0,
                                 (sizeof(nsfw_pid_item) * NSFW_MAX_PID));
                    if (EOK != retval)
                    {
                        NSFW_LOGERR("memset_s failed]retval=%d.\n", retval);
                        return -1;
                    }
                }
                g_master_ps_info = pid_info;

                MEM_STAT(NSFW_PS_MODULE, pzoneinfo.stname.aname, NSFW_SHMEM,
                         pzoneinfo.lenth);
                g_ps_info = pid_info;

                for (loop_alarm_id = ALARM_EVENT_BASE;
                     loop_alarm_id < ALARM_EVENT_MAX; loop_alarm_id++)
                {
                    g_omc_alm_state[loop_alarm_id].send_succ_flag = 1;
                    g_omc_alm_state[loop_alarm_id].current_alarm_state =
                        ALARM_CLEAN;
                    g_omc_alm_state[loop_alarm_id].resend_timer = NULL;
                }

                break;
            }
        case NSFW_PROC_MAIN:
            {

                (void) nsfw_mgr_reg_msg_fun(MGR_MSG_CHK_INIT_REQ,
                                            nsfw_ps_recv_hbt);
                (void) nsfw_mgr_reg_msg_fun(MGR_MSG_CHK_HBT_REQ,
                                            nsfw_ps_recv_hbt);
                pid_info = malloc(sizeof(nsfw_pid_item) * NSFW_MAX_PID);
                if (NULL == pid_info)
                {
                    NSFW_LOGERR("malloc mem failed!");
                    return -1;
                }

                retval =
                    memset_s(pid_info,
                             (sizeof(nsfw_pid_item) * NSFW_MAX_PID), 0,
                             (sizeof(nsfw_pid_item) * NSFW_MAX_PID));
                if (EOK != retval)
                {
                    NSFW_LOGERR("memset_s failed]retval=%d.\n", retval);
                    free(pid_info);
                    return -1;
                }

                g_ps_info = pid_info;

                pzoneinfo.stname.enowner = NSFW_PROC_MASTER;
                pid_info = nsfw_mem_zone_lookup(&pzoneinfo.stname);
                if (NULL == pid_info)
                {
                    NSFW_LOGERR("lookup pid_info failed!");
                    return -1;
                }

                g_master_ps_info = pid_info;
                break;
            }
        default:
            return 0;
    }

    ps_cfg->ps_info_size = NSFW_PS_INFO_MAX_COUNT;
    ps_cfg->ps_waite_exit_tvalue = NSFW_PS_WEXIT_TVLAUE_DEF;
    ps_cfg->net_link_buf = MAX_NET_LINK_BUF_DEF;

    INIT_LIST_HEAD(&(g_ps_runing_list));

    nsfw_mem_sppool pmpinfo;
    pmpinfo.enmptype = NSFW_MRING_MPMC;
    pmpinfo.usnum = ps_cfg->ps_info_size;
    pmpinfo.useltsize = sizeof(nsfw_ps_info);
    pmpinfo.isocket_id = NSFW_SOCKET_ANY;
    pmpinfo.stname.entype = NSFW_NSHMEM;
    if (-1 ==
        sprintf_s(pmpinfo.stname.aname, NSFW_MEM_NAME_LENTH, "%s",
                  "MAS_PS_INFOPOOL"))
    {
        NSFW_LOGERR("sprintf_s failed]");
        return -1;
    }
    ps_cfg->ps_info_pool = nsfw_mem_sp_create(&pmpinfo);

    if (!ps_cfg->ps_info_pool)
    {
        NSFW_LOGERR("alloc ps info pool_err");
        return -1;
    }

    MEM_STAT(NSFW_PS_MODULE, pmpinfo.stname.aname, NSFW_NSHMEM,
             nsfw_mem_get_len(ps_cfg->ps_info_pool, NSFW_MEM_SPOOL));

    if (NSFW_PROC_MASTER != proc_type)
    {
        return 0;
    }

    struct timespec time_left = { NSFW_PS_FIRST_CHK_TVLAUE, 0 };
    g_ps_chk_timer = (void *) nsfw_timer_reg_timer(NSFW_PS_CHK_TIMER, (void *) TRUE,    /* the first call will re-alloc all pid */
                                                   nsfw_ps_chk_timeout,
                                                   time_left);
    /* There may be latency from process exiting to /proc being updated, Master needs to check multiple times */
    int itv;
    for (itv = 1; itv < 5; itv++)
    {
        time_left.tv_sec += itv;        /* increasing interval */
        g_ps_chk_timer = (void *) nsfw_timer_reg_timer(NSFW_PS_CHK_TIMER, (void *) FALSE,       /* the latter calls should not re-alloc */
                                                       nsfw_ps_chk_timeout,
                                                       time_left);
    }

    if (TRUE != nsfw_ps_start_netlink())
    {
        return -1;
    }

    return 0;
}

/* *INDENT-OFF* */
NSFW_MODULE_NAME(NSFW_PS_MODULE)
NSFW_MODULE_PRIORITY(10)
NSFW_MODULE_DEPENDS(NSFW_MGR_COM_MODULE)
NSFW_MODULE_DEPENDS(NSFW_TIMER_MODULE)
NSFW_MODULE_INIT(nsfw_ps_module_init)
/* *INDENT-ON* */

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif /* __cplusplus */
