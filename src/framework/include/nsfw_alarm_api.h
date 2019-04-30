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

#ifndef _NSFW_ALARM_API_H_
#define _NSFW_ALARM_API_H_

//#include <sys/types.h>

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
#endif

#define ALARM_RESEND_TIMER_LENGTH 10

#define ALARM_ID_BASE_VALUE 27000

/* alarm ID for every event, when need add new alarm, here add a alarm_id define */
typedef enum _alarm_id
{
    ALARM_EVENT_BASE,
    ALARM_EVENT_NSTACK_RESOURCE_ALARM,
    ALARM_EVENT_NSTACK_NO_USE_1,
    ALARM_EVENT_NSTACK_MAIN_ABNORMAL_RESTART_FAIL,      /* daemon-stack exit, nStackMaster can't successfully restart */
    ALARM_EVENT_NSTACK_NO_USE_2,
    ALARM_EVENT_NSTACK_MAIN_EXIT_CAUSE_FD_FAIL, /* daemon-stack exit cause fd report err event */
    ALARM_EVENT_NSTACK_HOTFIX_ALM_ID = 1006,    /* used for hotfix activate */
    ALARM_EVENT_MAX
} enum_alarm_id;

typedef enum _alarm_flag
{
    ALARM_PRODUCT,
    ALARM_CLEAN,
    ALARM_HOTFIX,
    ALARM_MAX
} alarm_flag;

#define ALARM_ID_NOT_VALID(alarmId) (((alarmId) <= ALARM_EVENT_BASE) || ((alarmId) >= ALARM_EVENT_MAX))

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif
