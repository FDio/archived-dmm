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

#ifndef _PIA_COMMON_H_
#define _PIA_COMMON_H_

#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
#endif

#ifndef u32_t
typedef uint32_t u32_t;
#endif

#define SYS_HOST_INITIAL_PID 1

#define READ_FILE_BUFLEN  512
#define BUF_SIZE_FILEPATH 256

#define MAX_GET_PID_TIME 10

extern volatile pid_t g_sys_host_pid;

pid_t sys_get_hostpid_from_file(pid_t pid);
pid_t get_hostpid_from_file(u32_t pid);
pid_t get_hostpid_from_file_one_time(u32_t pid);
void get_exec_name_by_pid(pid_t pid, char *task_name, int task_name_len);
pid_t updata_sys_pid();

static inline pid_t get_sys_pid()
{
    if (SYS_HOST_INITIAL_PID == g_sys_host_pid)
        (void) sys_get_hostpid_from_file(getpid());
    return g_sys_host_pid;
}

#ifndef u64
typedef unsigned long long u64;
#endif

typedef struct nsfw_app_info
{
    int nsocket_fd;
    int sbr_fd;

    int hostpid;
    int pid;
    int ppid;
    int tid;
    u64 extend_member_bit;
} nsfw_app_info_t;

#define _dmm_packed __attribute__((__packed__))
#define _dmm_aliened(a) __attribute__((__aligned__(a)))
#define _dmm_cache_aligned _dmm_aliened(DMM_CACHE_LINE_SIZE)

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif
