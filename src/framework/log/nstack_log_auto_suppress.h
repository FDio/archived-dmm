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

#ifndef _NSTACK_LOG_SUPPRESS_H_
#define _NSTACK_LOG_SUPPRESS_H_

#include "types.h"
#include "nstack_log.h"

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C"{
/* *INDENT-ON* */
#endif /* __cplusplus */

#define NSFW_LOG_SUP_MODULE "nsfw_log_sup"

#define CTRL_BIT__SUPPRESSED (1 << 0)
#define CTRL_BIT__KEEP (1 << 1)

/* The threshold must be larger than the size of log_sup_table, otherwise the suppress report itself may be suppressed */
#define LOG_SUP_THRESH_DEFAULT 8192

/* Must be larger than the number of threads in non-App processes */
#define MAX_NUM_OF_LOG_SUP_TABLE 8

#define SET_BITS(x,bits) (x)|=(bits)
#define CLR_BITS(x,bits) (x)&=~(bits)
#define ISSET_BITS(x,bits) ((x)&(bits))

#define GET_TAG_FROM_FILE_AND_LINE(_file,_line) \
    (u64)(((u64)(_file) & 0x00FFFFFFFFFFFFFF) | ((u64)(_line) << 48))

typedef struct _log_sup_summary
{
    log_sup_table *tables[MAX_NUM_OF_LOG_SUP_TABLE];
    int table_cnt;
    volatile int lock;
} log_sup_summary;

extern __thread log_sup_table gt_log_sup_table;

inline int log_entry_cmp(const log_entry * left, const log_entry * right);
log_sup_node *malloc_one_node();
void free_one_node(log_sup_node * node);
void update_sup_table_on_timer(void);

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif /* __cplusplus */

#endif
