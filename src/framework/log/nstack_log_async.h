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

#ifndef _NSTACK_LOG_SOCK_H_
#define _NSTACK_LOG_SOCK_H_

#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <time.h>
#include <errno.h>
#include "types.h"
#include "nstack_log.h"

#define PRE_INIT_LOG_LENGTH 128
#define MAX_PRE_INIT_LOG_COUNT 256
#define MAX_BUFFER_LEN 2048     //buffer len for the domain socket recv

//Note: need match with _NLOG_TYPE in glog
enum _LOG_TYPE
{
    LOG_TYPE_NSTACK = 0,
    LOG_TYPE_OPERATION,
    LOG_TYPE_MASTER,
    LOG_TYPE_CTRL,
    LOG_TYPE_SEGMENT,
    LOG_TYPE_APP,
    LOG_TYPE_UNRECOGNIZED,
    MAX_LOG_TYPE
};

/*change the print level, not only has err*/

struct pre_init_info
{
    uint32_t level;     /**< Log level. */
    char log_buffer[PRE_INIT_LOG_LENGTH];
};

extern __thread unsigned int pre_log_nonreentry;

/*change the log type check*/
#define pre_log_shooting(_type,_level) \
        (((_type >= MAX_LOG_TYPE) || (g_nstack_logs[LOGASYNC].level < _level) || (!nstack_log_level_valid(_level))) ? FALSE: TRUE)

#define NS_PTHREADLOG(_type,_level,fmt, ...) \
{\
    if (pre_log_shooting(_type, _level) && (0 == pre_log_nonreentry))\
    {\
        pre_log_nonreentry = 1;\
        nstack_log_print_buffer(_type, _level, \
            "%d %s:%d] %d,%s <NSTHREAD>" fmt "\r\n", (int)syscall(SYS_gettid), GET_FILE_NAME(__FILE__), \
            __LINE__, getpid(),__func__, ##__VA_ARGS__);\
        pre_log_nonreentry = 0;\
    }\
}

int nstack_log_server_init(int proc_type);

int nstack_log_client_init(int proc_type);

int nstack_log_client_send(int file_type, char *buffer, size_t buflen);

int nstack_log_server_flush(int proc_type, unsigned long long timeout);

bool nstack_log_level_valid(uint32_t level);

int get_pre_init_log_count();

int get_pre_init_log_buffer(struct pre_init_info *pre_buf, uint32_t size);

char *get_level_desc(uint32_t level);

int nstack_log_get_prefix(uint32_t level, char *buffer, uint32_t length);

void nstack_log_print_buffer(uint32_t log_type, uint32_t level,
                             const char *format, ...);

#endif /*_NSTACK_LOG_SOCK_H_*/
