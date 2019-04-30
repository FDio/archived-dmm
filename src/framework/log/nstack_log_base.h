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

#ifndef _NSTACK_LOG_BASE_H_
#define _NSTACK_LOG_BASE_H_

#include "types.h"
#include "nstack_log.h"

#define LOG_LEVEL_EMG "emg"
#define LOG_LEVEL_ERR "err"
#define LOG_LEVEL_WAR "war"
#define LOG_LEVEL_DBG "dbg"
#define LOG_LEVEL_INF "inf"

#define STACKPOOL_LOG_NAME "running.log"

#define OPERATION_LOG_NAME "operation.log"

#define MASTER_LOG_NAME "master.log"

#define OMC_CTRL_LOG_NAME "omc_ctrl.log"

#define FAILURE_LOG_NAME "fail_dump.log"

#define FLUSH_TIME 30

#define APP_LOG_SIZE 30
#define APP_LOG_COUNT 10
#define APP_LOG_PATH "/var/log"
#define APP_LOG_NAME "nStack_nSocket.log"

struct log_ctrl_info
{
    u32 expire_time;
    u32 unprint_count;
    struct timespec last_log_time;
};

/* NS_LOG_CTRL use to inhibit the repeated log*/
/* add the non reentry protection */
extern __thread unsigned int nstack_log_nonreentry;

/* if buf can't load more data(in other words, sprintf_s return -1 and set buf[pos]='\0'),
   print the existing data, and once more try to load the data, to the beginning of the buffer,
   if still failed, return -1.*/
#define NSDFX_CACHE_RETURN(pos, buf, buflen, fmt, ...) do { \
    int cache_ret = 0; \
    if ((pos) < (buflen)) { \
        cache_ret = sprintf_s((buf) + (pos), (buflen) - (pos), fmt, ##__VA_ARGS__); \
        if (-1 == cache_ret) { \
            NSDFX_LOGINF("%s", (buf)); \
            (pos) = 0; \
            cache_ret = sprintf_s((buf), (buflen), fmt, ##__VA_ARGS__); \
            if (-1 == cache_ret){ \
                NSDFX_LOGERR("NSDFX_CACHE_RETURN sprintf_s failed second time"); \
                return -1; \
            } \
        } \
        (pos) += cache_ret; \
    } else { \
        NSDFX_LOGERR("DFX cache buffer overflow!!!!!!"); \
        return -1; \
        } \
}while(0)

#define NSDFX_CACHE_FLAG_RETURN(log_flag,pos, buf, buflen, fmt, ...) do { \
    if (log_flag) \
    { \
        NSDFX_CACHE_RETURN(pos, buf, buflen, fmt, ##__VA_ARGS__); \
    } \
}while(0)

/* Utilities, placed here for convenience */
#define STRING_IS_VALID_WITH_LENGTH(str,len) ((str) && (*str) && (strlen(str) < len))

#define EACH_OF_2_ITEMS_NOT_NULL(a0,a1)             ((a0)&&(a1))
#define EACH_OF_3_ITEMS_NOT_NULL(a0,a1,a2)          ((a0)&&(a1)&&(a2))
#define EACH_OF_4_ITEMS_NOT_NULL(a0,a1,a2,a3)       ((a0)&&(a1)&&(a2)&&(a3))
#define EACH_OF_5_ITEMS_NOT_NULL(a0,a1,a2,a3,a4)    ((a0)&&(a1)&&(a2)&&(a3)&&(a4))
#define EACH_OF_6_ITEMS_NOT_NULL(a0,a1,a2,a3,a4,a5) ((a0)&&(a1)&&(a2)&&(a3)&&(a4)&&(a5))
/* Utilities, placed here for convenience */

#endif /*_NSTACK_LOG_BASE_H_*/
