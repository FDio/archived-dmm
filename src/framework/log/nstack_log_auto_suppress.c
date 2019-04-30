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

/*==============================================*
 *      include header files                    *
 *----------------------------------------------*/
#include "nsfw_init_api.h"
#include "nstack_log_async.h"
#include "nstack_log_auto_suppress.h"
#include "nsfw_fd_timer_api.h"
#include "nsfw_mgr_com_api.h"
#include "nstack_securec.h"
#include <unistd.h>
#include "nstack_log_auto_suppress_rb_tree.h"

/*==============================================*
 *      project-wide global variables           *
 *----------------------------------------------*/
__thread log_sup_table gt_log_sup_table = { 0 };
NSTACK_STATIC log_sup_summary g_log_sup_summary = { {0, 0, 0, 0, 0, 0, 0, 0}
, 0, 0
};

NSTACK_STATIC u32 g_log_sup_thresh = LOG_SUP_THRESH_DEFAULT;

/*==============================================*
 *      routines' or functions' implementations *
 *----------------------------------------------*/
inline bool is_log_sup_switched_off(const u8 module)
{
    return ((MAX_LOG_MODULE > module) && g_nstack_logs[module].suppress_off);
}

inline log_sup_table *get_log_sup_table_addr()
{
    return &gt_log_sup_table;
}

inline int log_entry_cmp(const log_entry * left, const log_entry * right)
{
    u64 key_left = GET_TAG_FROM_FILE_AND_LINE(left->file, left->line);
    u64 key_right = GET_TAG_FROM_FILE_AND_LINE(right->file, right->line);

    if (key_left > key_right)
    {
        return 1;
    }
    else if (key_left < key_right)
    {
        return -1;
    }
    else
    {
        return 0;
    }
}

/* CAUTION: Only given the limited scenario in regard of `gt_log_sup_table` can we simplify the malloc/free mechanism like below.
 * 1. `gt_log_sup_table` is thread-independent;
 * 2. there are only 2 possible malloc scenario:
 *     (a) when table is not full, create a new node;
 *     (b) when table is full, add a node right after deleting the old one, so we just take its place */
log_sup_node *malloc_one_node()
{
    if (gt_log_sup_table.count >= gt_log_sup_table.size)
    {
        /* full or uninited, don't print log here */
        return NULL;
    }
    log_sup_node *node;
    if (gt_log_sup_table.just_been_freed)
    {
        /* when table is full, add a node right after deleting the old one, so we just take its place */
        node = gt_log_sup_table.just_been_freed;
    }
    else
    {
        /* when table is not full, create a new node */
        node = gt_log_sup_table.nodepool + gt_log_sup_table.count;
    }
    gt_log_sup_table.count++;

    return node;
}

void free_one_node(log_sup_node * node)
{
    gt_log_sup_table.just_been_freed = node;    /* mark the place */
    gt_log_sup_table.count--;
}

/* CAUTION: log printing can be used in this function ONLY when we have confirmed that
 * gt_log_sup_table is initialized, whether successfully or not. */
log_sup_table *init_sup_table(int table_size)
{
    /* Prevent `g_log_sup_thresh` from being optimized out, so that we can enforce it by gdb. Not needed in UT */
    g_log_sup_thresh = LOG_SUP_THRESH_DEFAULT;
    gt_log_sup_table.root = NULL;
    gt_log_sup_table.nodepool = NULL;
    gt_log_sup_table.just_been_freed = NULL;
    gt_log_sup_table.size = 0;
    gt_log_sup_table.count = 0;

    if (table_size <= 0 || table_size > LOG_SUP_TABLE_SIZE_UPPER_LIMIT)
    {
        NSFW_LOGERR("invalid gt_log_sup_table size=%d!", table_size);
        return NULL;
    }

    gt_log_sup_table.nodepool =
        (log_sup_node *) malloc(table_size * sizeof(log_sup_node));
    if (NULL == gt_log_sup_table.nodepool)
    {
        NSFW_LOGERR("malloc gt_log_sup_table failed!");
        return NULL;
    }

    int ret = memset_s(gt_log_sup_table.nodepool,
                       (table_size * sizeof(log_sup_node)), 0,
                       (table_size * sizeof(log_sup_node)));
    if (EOK != ret)
    {
        free(gt_log_sup_table.nodepool);
        gt_log_sup_table.nodepool = NULL;
        NSFW_LOGERR("memset_s gt_log_sup_table failed! ret=%d", ret);
        return NULL;
    }

    int dlc = 10000;

    while (!__sync_bool_compare_and_swap(&g_log_sup_summary.lock, 0, 1))        //LOCK
    {
        if (--dlc == 0)
        {
            free(gt_log_sup_table.nodepool);
            gt_log_sup_table.nodepool = NULL;
            NSFW_LOGERR("can't get the lock of g_log_sup_summary");
            return NULL;
        }
        /* use nanosleep() instead of usleep() */
        struct timespec delay;
        delay.tv_sec = 0;
        delay.tv_nsec = 10000;
        (void) nanosleep(&delay, NULL); /* don't care for precission, so no need to check return value or output param */
    }
    if (g_log_sup_summary.table_cnt < MAX_NUM_OF_LOG_SUP_TABLE)
    {
        g_log_sup_summary.tables[g_log_sup_summary.table_cnt] =
            &gt_log_sup_table;
        g_log_sup_summary.table_cnt++;
        g_log_sup_summary.lock = 0;     //UNLOCK
    }
    else
    {
        free(gt_log_sup_table.nodepool);
        gt_log_sup_table.nodepool = NULL;
        g_log_sup_summary.lock = 0;     //UNLOCK
        NSFW_LOGERR("g_log_sup_summary is full");
        return NULL;
    }

    gt_log_sup_table.size = table_size;
    NSFW_LOGINF("init gt_log_sup_table succ]nodepool=%p",
                gt_log_sup_table.nodepool);
    return &gt_log_sup_table;
}

/* Mid-layer for datastruture methods. DO NOT print log in these functions - Begin */
NSTACK_STATIC inline log_sup_node *_log_sup_search(const log_entry * entry,
                                                   log_sup_table * table)
{
    return __log_sup_rb_search(entry, table->root);
}

NSTACK_STATIC inline void _log_sup_erase(log_sup_node * node,
                                         log_sup_table * table)
{
    return __log_sup_rb_erase(node, &(table->root));
}

NSTACK_STATIC inline log_sup_node *_log_sup_insert(log_entry * entry,
                                                   log_sup_table * table)
{
    return __log_sup_rb_insert(entry, &(table->root));
}

/* Mid-layer for datastruture methods. DO NOT print log in these functions - End */

static inline int is_node_to_delete(log_entry * entry)
{
    return !ISSET_BITS(entry->ctrl_bits, CTRL_BIT__KEEP);
}

bool update_sup_table_on_logging(const char *file, const u16 line,
                                 const u8 log_type, const u16 level,
                                 log_sup_table * table, u32 * dup_cnt)
{
    log_entry ent;
    ent.ctrl_bits = 0;
    ent.level = level;
    ent.log_type = log_type;
    ent.last_epoch_dup_cnt = 0;
    ent.file = file;
    ent.line = line;

    if (NULL == table->nodepool)        ///not inited, abort
    {
        return FALSE;
    }

    log_sup_node *node = _log_sup_search(&ent, table);
    if (NULL == node)           //no match found, insert one
    {
        if (NULL == (node = _log_sup_insert(&ent, table)))      //table is full, try to replace
        {
            log_sup_node *node2del = NULL;
            int recur_cnt = table->size;
            __log_sup_rb_traversal_preorder(table->root, is_node_to_delete,
                                            &node2del, &recur_cnt);
            if (node2del)
            {
                _log_sup_erase(node2del, table);
                node = _log_sup_insert(&ent, table);
                if (NULL == node)
                {
                    /* should never happen */
                    return FALSE;       /* The conservative choice is not to suppress */
                }
            }
            else
            {
                /* No entry can be replaced, should happen very rarely */
                return FALSE;
            }
        }
    }

    /* ASSERT: node != NULL when reaching here */
    node->entry.last_epoch_dup_cnt++;
    if (dup_cnt)                /* can be NULL */
    {
        *dup_cnt = node->entry.last_epoch_dup_cnt;
    }
    SET_BITS(node->entry.ctrl_bits, CTRL_BIT__KEEP);
    if (node->entry.last_epoch_dup_cnt > g_log_sup_thresh)
    {
        SET_BITS(node->entry.ctrl_bits, CTRL_BIT__SUPPRESSED);
    }
    return ISSET_BITS(node->entry.ctrl_bits, CTRL_BIT__SUPPRESSED);
}

static inline void print_suppressed_log(log_entry * entry)
{
    if (ISSET_BITS(entry->ctrl_bits, CTRL_BIT__SUPPRESSED))
    {
        u16 _level = entry->level;
        u8 _module = entry->log_type;

        if (entry->last_epoch_dup_cnt > g_log_sup_thresh)
        {
            NS_LOGPID(_module, "SUP", _level, "%s:%u repeated %u times",
                      GET_FILE_NAME(entry->file), entry->line,
                      entry->last_epoch_dup_cnt);
        }
        else
        {
            NS_LOGPID(_module, "SUP", _level,
                      "%s:%u repeated %u times (may release)",
                      GET_FILE_NAME(entry->file), entry->line,
                      entry->last_epoch_dup_cnt);
        }

    }
}

static inline void update_log_sup_ctrl(log_entry * entry)
{
    if (entry->last_epoch_dup_cnt > g_log_sup_thresh)
    {
        SET_BITS(entry->ctrl_bits, (CTRL_BIT__SUPPRESSED | CTRL_BIT__KEEP));
    }
    else
    {
        CLR_BITS(entry->ctrl_bits, (CTRL_BIT__SUPPRESSED | CTRL_BIT__KEEP));
    }
    entry->last_epoch_dup_cnt = 0;
}

static inline int print_update_sup_entry(log_entry * entry)
{
    print_suppressed_log(entry);
    update_log_sup_ctrl(entry);
    return 0;
}

void update_sup_table_on_timer(void)
{
    int i;
    for (i = 0; i < g_log_sup_summary.table_cnt; i++)
    {
        log_sup_table *table = g_log_sup_summary.tables[i];
        int recur_cnt = table->size;
        __log_sup_rb_traversal_preorder(table->root, print_update_sup_entry,
                                        NULL, &recur_cnt);
    }
}

int nsfw_log_sup_timeout(u32 timer_type, void *data)
{
    update_sup_table_on_timer();
    struct timespec time_left = { 1, 0 };
    void *ptr = (void *) nsfw_timer_reg_timer(777, NULL, nsfw_log_sup_timeout,
                                              time_left);
    if (!ptr)
    {
        NSFW_LOGERR("re-register log_sup_timer fail!");
        return FALSE;
    }
    return TRUE;
}

int nsfw_log_sup_module_init(void *param)
{
    u32 proc_type = (u32) ((long long) param);
    int table_size;

    switch (proc_type)
    {
        case NSFW_PROC_MASTER:
            table_size = LOG_SUP_TABLE_SIZE_FOR_MASTER;
            break;
        case NSFW_PROC_MAIN:
            table_size = LOG_SUP_TABLE_SIZE_FOR_MAIN;
            break;
        default:
            return 0;
    }

    /* Init log suppression for this thread */
    if (NULL == init_sup_table(table_size))
    {
        NSFW_LOGWAR("log suppression init failed in main thread");
    }

    struct timespec time_left = { 1, 0 };
    void *ptr = (void *) nsfw_timer_reg_timer(777, NULL, nsfw_log_sup_timeout,
                                              time_left);
    if (!ptr)
    {
        NSFW_LOGERR("init log_sup_timer fail!");
        return -1;
    }

    NSFW_LOGINF("init log_sup_module succ");
    return 0;
}

/* *INDENT-OFF* */
NSFW_MODULE_NAME(NSFW_LOG_SUP_MODULE)
NSFW_MODULE_PRIORITY(10)
NSFW_MODULE_DEPENDS(NSFW_TIMER_MODULE)
NSFW_MODULE_INIT(nsfw_log_sup_module_init)
/* *INDENT-ON* */
