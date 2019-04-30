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

#include <string.h>
#include <time.h>
#include <errno.h>
#include "nstack_log.h"
#include "nstack_securec.h"
#include "pid_common.h"

volatile pid_t g_sys_host_pid = SYS_HOST_INITIAL_PID;

/*****************************************************************************
*   Prototype    : get_hostpid_from_file
*   Description  : get host pid by sub namespace pid in docker
*   Input        : uint32_t pid
*   Output       : None
*   Return Value : uint32_t
*   Calls        :
*   Called By    :
*****************************************************************************/
pid_t sys_get_hostpid_from_file(pid_t pid)
{
    g_sys_host_pid = get_hostpid_from_file(pid);
    NSRTP_LOGDBG("ok]cur pid=%d, input pid=%d", g_sys_host_pid, pid);
    return g_sys_host_pid;
}

pid_t get_hostpid_from_file(u32_t pid)
{
    pid_t ret_pid = SYS_HOST_INITIAL_PID;
    int i = 0;
    ret_pid = get_hostpid_from_file_one_time(pid);
    while (0 == ret_pid || ret_pid == SYS_HOST_INITIAL_PID)
    {
        i++;
        if (i > MAX_GET_PID_TIME)
        {
            NSFW_LOGERR("get pid failed]pid=%u,hostpid=%d", pid, ret_pid);
            break;
        }
        sys_sleep_ns(0, 5000000);
        ret_pid = get_hostpid_from_file_one_time(pid);
    }

    return ret_pid;
}

pid_t get_hostpid_from_file_one_time(u32_t pid)
{
    int retVal;
    char path[READ_FILE_BUFLEN] = { 0 };
    char buf[READ_FILE_BUFLEN] = { 0 };
    char fmt[READ_FILE_BUFLEN] = { 0 };
    char out[READ_FILE_BUFLEN] = { 0 };
    char task_name[BUF_SIZE_FILEPATH] = { 0 };
    pid_t hostpid = SYS_HOST_INITIAL_PID;       //init to an invalid value
    /*There are some unsafe function ,need to be replace with safe function */
    get_exec_name_by_pid(pid, task_name, BUF_SIZE_FILEPATH);

    /* adjust the position of HAVE_STACKTRACE and modify to snprintf_s */
    if (0 == task_name[0])
    {
        NSRTP_LOGERR("get task_name failed");
        return hostpid;
    }

    /*There are some unsafe function ,need to be replace with safe function */
    retVal = sprintf_s(fmt, sizeof(fmt), "%s%s", task_name, " (%s");
    if (-1 == retVal)
    {
        NSRTP_LOGERR("sprintf_s failed]ret=%d", retVal);
        return hostpid;
    }
    retVal = sprintf_s(path, sizeof(path), "/proc/%u/sched", pid);
    if (-1 == retVal)
    {
        NSRTP_LOGERR("sprintf_s failed]ret=%d", retVal);
        return hostpid;
    }
    FILE *fp = fopen(path, "r");
    if (NULL != fp)
    {
        if (fgets(buf, READ_FILE_BUFLEN - 1, fp) == NULL)
        {
            fclose(fp);
            return hostpid;
        }
        fclose(fp);
        /* Compiler needs "fmt" to be like "%s%s" to
           understand. But we have "fmt" already prepared and used here. It can
           be suppressed, not an issue
         */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
        /*There are some unsafe function ,need to be replace with safe function */
        retVal = sscanf_s(buf, fmt, out, READ_FILE_BUFLEN);
#pragma GCC diagnostic pop
        if (-1 == retVal)
        {
            NSPOL_LOGERR("sscanf_s failed]ret=%d", retVal);
            return hostpid;
        }
        /*There are some unsafe function ,need to be replace with safe function */
    }

    hostpid = (pid_t) strtol(out, NULL, 0);
    if (hostpid == 0)
    {
        hostpid = 1;
    }

    return hostpid;
}

void get_exec_name_by_pid(pid_t pid, char *task_name, int task_name_len)
{
    int retVal;
    char path[READ_FILE_BUFLEN] = { 0 };
    char buf[READ_FILE_BUFLEN] = { 0 };
    /* There are some unsafe function ,need to be replace with safe function */
    retVal = sprintf_s(path, sizeof(path), "/proc/%d/status", pid);
    if (-1 == retVal)
    {
        NSRTP_LOGERR("sprintf_s failed]ret=%d", retVal);
        return;
    }
    FILE *fp = fopen(path, "r");
    if (NULL != fp)
    {
        if (fgets(buf, READ_FILE_BUFLEN - 1, fp) == NULL)
        {
            fclose(fp);
            return;
        }
        fclose(fp);
        /*There are some unsafe function ,need to be replace with safe function */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-extra-args"
        retVal = sscanf_s(buf, "%*s %s", task_name, task_name_len);
#pragma GCC diagnostic pop
        if (1 != retVal)
        {
            NSSOC_LOGERR("sscanf_s failed]ret=%d", retVal);
            return;
        }
    }
}

pid_t updata_sys_pid()
{
    g_sys_host_pid = SYS_HOST_INITIAL_PID;
    return get_sys_pid();
}
