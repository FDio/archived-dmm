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

#ifndef NSTACK_SHARE_RES_H
#define NSTACK_SHARE_RES_H

#include <stdint.h>
#include "nstack_log.h"
#include "dmm_spinlock.h"

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
#endif

#define NSTACK_VERSION_SHM "nstack_version"
#define NSTACK_VERSION_LEN 128
COMPAT_PROTECT (NSTACK_VERSION_LEN, 128);
#define MAX_UNMATCH_VER_CNT 32
COMPAT_PROTECT (MAX_UNMATCH_VER_CNT, 32);

#define NSTACK_GLOBAL_TICK_SHM "nstack_global_tick"

typedef struct unmatch_ver_info
{
  int unmatch_count;
  char lib_version[NSTACK_VERSION_LEN];
  char first_time_stamp[LOG_TIME_STAMP_LEN];
} unmatch_ver_info_t;

int nstack_init_share_res ();
int nstack_attach_share_res ();
dmm_spinlock_t *nstack_get_fork_share_lock ();

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif
