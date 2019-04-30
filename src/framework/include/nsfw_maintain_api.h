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

#ifndef _NSFW_MEM_STAT_API_H
#define _NSFW_MEM_STAT_API_H

#include "types.h"
#include "nsfw_mgr_com_api.h"
#include "compiling_check.h"
#include <time.h>

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C"{
/* *INDENT-ON* */
#endif /* __cplusplus */

/*################MEM_STAT######################*/
#define NSFW_MEM_MODULE_LEN 32
#define NSFW_MEM_NAME_LEN   64

#define OMC_PROC_MM "omc_proc_maintain"

#define MEM_STAT(module, mem_name, mem_type, mem_size)\
    nsfw_mem_stat(module, mem_name, mem_type, mem_size)

extern void nsfw_mem_stat(char *module, char *mem_name, u8 mem_type,
                          u64 mem_size);
extern void nsfw_mem_stat_print();
/*##############################################*/

/*################SRV_CTRL######################*/
typedef enum _nsfw_srv_ctrl_state
{
    NSFW_SRV_CTRL_RESUME = 1,
    NSFW_SRV_CTRL_SUSPEND = 2
} nsfw_srv_ctrl_state;

typedef struct _nsfw_srv_ctrl_msg
{
    nsfw_srv_ctrl_state srv_state;
    u16 rsp_code;
} nsfw_srv_ctrl_msg;
extern u8 nsfw_srv_ctrl_send(nsfw_srv_ctrl_state state, u8 rsp_flag);
/*#############################################*/

/*#################RES_MGR######################*/
#define SPL_RES_MGR_MODULE "spl_res_mgr"

typedef enum _nsfw_res_scan_type
{
    NSFW_RES_SCAN_ARRAY = 0,
    NSFW_RES_SCAN_SPOOL,
    NSFW_RES_SCAN_MBUF,
    NSFW_RES_SCAN_MAX
} nsfw_res_scan_type;

typedef int (*nsfw_res_free_fun) (void *pdata);

typedef struct _nsfw_res_scn_cfg
{
    u8 type;                    /*nsfw_res_scan_type */
    u8 force_free_percent;      /*if the resource free percent below this vlaue, begin to force free the element */
    u16 force_free_chk_num;     /*if the check count beyone this vlaue, call free fun release this element */
    u16 alloc_speed_factor;     /*alloc fast with higher value */

    u32 num_per_cyc;            /*define the element number in one scan cycle process and increase chk_count of every element */
    u32 total_num;              /*total number of elements */
    u32 elm_size;               /*element size */
    u32 res_mem_offset;         /*the nsfw_res offset from the element start */

    void *data;                 /*the array addr or spool addr */
    void *mgr_ring;

    nsfw_res_free_fun free_fun;
} nsfw_res_scn_cfg;

typedef struct _nsfw_res_mgr_item_cfg
{
    nsfw_res_scn_cfg scn_cfg;
    u32 cons_head;
    u32 prod_head;
    u32 free_percent;
    u32 last_scn_idx;
    u64 force_count;
} nsfw_res_mgr_item_cfg;

#define NSFW_MAX_RES_SCAN_COUNT 256

extern u8 nsfw_res_mgr_reg(nsfw_res_scn_cfg * cfg);
extern i32 nsfw_proc_start_with_lock(u8 proc_type);
extern i32 nstack_record_pid_check_memory(u8 proc_type);

/*#############################################*/

/*#################VER_MGR######################*/
#define NSFW_VER_MGR_MODULE "nsfw_ver_mgr"

typedef enum _nsfw_ver_mgr_state
{
    NSFW_VER_NULL = 0,
    NSFW_VER_UPG = 1,
    NSFW_VER_RBK = 2,
    NSFW_VER_QRY = 3,
    NSFW_VER_READY_TO_RESTART = 4
} nsfw_ver_mgr_state;

typedef enum _nsfw_ver_mgr_err
{
    NSFW_OK = 0,
    NSFW_STATE_IN_UPG = 100,
    NSFW_INTER_FALIED = 120,
    NSFW_POOL_NULL = 121,

} nsfw_ver_mgr_err;

#define NSTACK_MAX_VERSION_LEN 40
#define NSTACK_MAX_MODULE_LEN 20
#define NSTACK_MAX_BUILDTIME_LEN 32

typedef struct _nsfw_ver_mgr_msg
{
    nsfw_ver_mgr_state ver_state;
    u16 rsp_code;
    char src_ver[NSTACK_MAX_VERSION_LEN];
    char dst_ver[NSTACK_MAX_VERSION_LEN];
    char module_name[NSTACK_MAX_MODULE_LEN];
    char build_time[NSTACK_MAX_BUILDTIME_LEN];
} nsfw_ver_mgr_msg;
extern u8 nsfw_ver_mgr_rsq(u16 rsp_code, u32 src_pid);

typedef struct _nsfw_ver_info
{
    char version[NSTACK_MAX_VERSION_LEN];
    char module_name[NSTACK_MAX_MODULE_LEN];
    char build_time[NSTACK_MAX_BUILDTIME_LEN];
} nsfw_ver_info;

typedef enum _nsfw_run_type
{
    NSFW_RUN_NULL = 0,
    NSFW_RUN_FIRST = 1,
    NSFW_RUN_NORMAL_RESTART,
    NSFW_RUN_RESTART,
    NSFW_RUN_STOP,
    NSFW_RUN_FREQUENTLY
} nsfw_run_type;

typedef enum _nsfw_init_state
{
    NSFW_INIT_SUCESS = 1,
    NSFW_INIT_MEMADDR_ERR = 2
} nsfw_init_state;

typedef struct _nsfw_init_nty_msg
{
    nsfw_init_state init_state;
    u16 rsp_code;
} nsfw_init_nty_msg;

u8 nsfw_init_result_send(u8 local_proc, nsfw_init_state state, u8 rsp_flag);

extern int g_cur_upg_state;
extern int g_start_type;

typedef enum _nsfw_exit_code
{
    NSFW_EXIT_SUCCESS = 0,
    NSFW_EXIT_FAILED = 1,
    NSFW_EXIT_DST_ERROR = 2,
    NSFW_EXIT_TIME_OUT = 3,

    NSFW_EXIT_MAX_COM_ERR = 31,
} nsfw_exit_code;

extern int nsfw_vermgr_module_init(void *param);
/*#############################################*/

/*#################SOFT_PARAM##################*/
#define NSFW_SOFT_PARAM_MODULE "nsfw_soft_param"

typedef struct _nsfw_soft_param_msg
{
    u32 param_name;
    u32 rsp_code;
    u8 param_value[NSFW_MGR_MSG_BODY_LEN - sizeof(u32) - sizeof(u32)];
}
nsfw_soft_param_msg;

typedef enum _nsfw_soft_param
{
    NSFW_DBG_MODE_PARAM = 1,
    NSFW_HBT_TIMER = 2,
    NSFW_HBT_COUNT_PARAM = 3,
    NSFW_APP_EXIT_TIMER = 4,
    NSFW_SRV_RESTORE_TIMER = 5,
    NSFW_APP_RESEND_TIMER = 6,
    NSFW_APP_SEND_PER_TIME = 7,
    NSFW_TCP_OOSLE_PARAM = 8,

    NSFW_MAX_SOFT_PARAM = 1024
} nsfw_soft_param;

typedef int (*nsfw_set_soft_fun) (u32 param, char *buf, u32 buf_len);
extern u8 nsfw_soft_param_reg_fun(u32 param_name, nsfw_set_soft_fun fun);
extern u8 nsfw_soft_param_reg_int(u32 param_name, u32 size, u32 min, u32 max,
                                  u64 * data);

extern void nsfw_set_soft_para(fw_poc_type proc_type, u32 para_name,
                               void *value, u32 size);

extern int nsfw_isdigitstr(const char *str);
#define NSFW_REG_SOFT_INT(_param,_data,_min, _max) nsfw_soft_param_reg_int(_param,sizeof(_data),_min,_max,(u64*)&_data)
/*#############################################*/

/*################# SPLNET ######################*/
#define NSFW_FAU_INJ_MODULE "nsfw_splnet"

typedef enum
{
    SPLNET_ACTION_NULL = 0,
    SPLNET_ACTION_SETDROP,
    SPLNET_ACTION_GETDROP,
    SPLNET_ACTION_BONDSWITCH,
    SPLNET_ACTION_GETBONDPRI,
    SPLNET_ACTION_MAX
} splnet_action;

#define MAX_NETIF_NAME_LEN 256
#define MAX_NETIF_NUM 32

typedef struct _nsfw_splnet_msg
{
    struct timeval start_time;
    splnet_action action;
    char name[MAX_NETIF_NAME_LEN];      //means eth list when fault_inject, or network name when bondswitch
    int drop_numer;
    int drop_denom;
    int exp_time;
} nsfw_splnet_msg;

extern struct netif_fault_ctl *alloc_netif_fault_ctl_entry();
extern bool do_drop_packet(struct netif_fault_ctl *fault_ctl);

/*#############################################*/

/*#################LOG_CONFIG##################*/
#define NSFW_LOG_CFG_MODULE "nsfw_log_cfg"

#define NSFW_MODULE_NAME_LEN 20
#define NSFW_LOG_LEVEL_LEN 10
#define NSFW_LOG_VALUE_LEN 256

typedef struct _nsfw_set_log_msg
{
    u16 rsp_code;
    char module[NSFW_MODULE_NAME_LEN];
    char log_level[NSFW_LOG_VALUE_LEN];
} nsfw_set_log_msg;
/*#############################################*/

/*################## DFX ######################*/
#define MAX_DFX_QRY_RES_LEN 28

#define SPL_DFX_RES_ALL         "all"
#define SPL_DFX_RES_QUEUE       "queue"
#define SPL_DFX_RES_CONN        "conn"
#define SPL_DFX_RES_L2TO4       "l2to4"
#define SPL_DFX_RES_UNMATCH     "version"
#define SPL_DFX_RES_SOCKT_CB    "socketcb"
#define SPL_DFX_RES_RTP_MEMPOOL "mbufpool"
#define SPL_DFX_RES_PCBLIST     "pcblist"
#define SPL_DFX_RES_ARPLIST     "arplist"

typedef enum
{
    DFX_ACTION_SNAPSHOT,
    DFX_ACTION_RST_STATS,
    DFX_ACTION_SWITCH,
    DFX_ACTION_GET_CONTAINER_STAT,
    DFX_ACTION_GET_CONTAINER_L4_STAT,
    DFX_ACTION_MAX
} dfx_module_action;

typedef struct _nsfw_dfx_qry_msg
{
    dfx_module_action action;
    char resource[MAX_DFX_QRY_RES_LEN];
    char flag;                  //for snapshot print "all"
} nsfw_dfx_qry_msg;

typedef struct _nsfw_dfx_qry_container_stat_msg
{
    dfx_module_action action;
    char container_id[256];     //TODO
} nsfw_dfx_qry_container_stat_msg;

typedef enum
{
    QUERY_ACTION_GET,
    QUERY_ACTION_MAX
} query_action;

typedef struct _nsfw_qry_msg
{
    query_action action;
    char resource[MAX_DFX_QRY_RES_LEN];
} nsfw_get_qry_msg;

typedef enum _qry_errcode
{
    QUERY_OK = 0,
    QUERY_INTERNAL_ERR = 1,
    QUERY_CONTAINER_STAT_NOT_SURPPORTED = 32,
    QUERY_NO_SUCH_CONTAINER = 33,
    QUERY_ERR_MAX = 127
} qry_errcode;

/*##################DFX#########################*/

/*#################for tcpdump#####################*/

#ifndef nstack_min
#define nstack_min(a, b) (a) < (b) ? (a) : (b)
#endif

#define GET_CUR_TIME(ptime) \
    (void)clock_gettime(CLOCK_MONOTONIC, ptime);

#define TCPDUMP_MODULE "tcpdump_tool"

#define MIN_DUMP_MSG_NUM (4 * 1024)
#define MAX_DUMP_MSG_NUM (64 * 1024)

#define DUMP_NO_LIMIT 0         //must be set to 0 dumping only packets header for release

/* *INDENT-OFF* */
#if DUMP_NO_LIMIT
#define DUMP_MSG_SIZE 1515      // can not be less than 14
COMPAT_PROTECT_RETURN (DUMP_MSG_SIZE, 1515)
#else
#define DUMP_MSG_SIZE 128       // can not be less than 14
COMPAT_PROTECT_RETURN (DUMP_MSG_SIZE, 128)
#endif
/* *INDENT-ON* */

#define DEFAULT_DUMP_TIME 600
#define MAX_DUMP_TIME 86400
#define MIN_DUMP_TIME 1

#define MAX_DUMP_TASK 16
#define DUMP_HBT_INTERVAL 2
#define DUMP_HBT_CHK_INTERVAL 4
#define DUMP_TASK_HBT_TIME_OUT 30

#define DUMP_SHMEM_RING_NAME "tcpdump_ring"
#define DUMP_SHMEM_POOL_NAME "tcpdump_pool"

/* for multi-dump */
#define DUMP_SHMEM_INFO_NAME_MST "tcpdump_infozone_mst"
#define DUMP_SHMEM_INFO_NAME_SLV "tcpdump_infozone_slv"

#define DUMP_SHMEM_RING_NAME_MST "tcpdump_ring_mst"
#define DUMP_SHMEM_POOL_NAME_MST "tcpdump_pool_mst"

#define DUMP_SHMEM_RING_NAME_SLV_0 "tcpdump_ring_slv_0"
#define DUMP_SHMEM_POOL_NAME_SLV_0 "tcpdump_pool_slv_0"
#define DUMP_SHMEM_RING_NAME_SLV_1 "tcpdump_ring_slv_1"
#define DUMP_SHMEM_POOL_NAME_SLV_1 "tcpdump_pool_slv_1"
#define DUMP_SHMEM_RING_NAME_SLV_2 "tcpdump_ring_slv_2"
#define DUMP_SHMEM_POOL_NAME_SLV_2 "tcpdump_pool_slv_2"
#define DUMP_SHMEM_RING_NAME_SLV_3 "tcpdump_ring_slv_3"
#define DUMP_SHMEM_POOL_NAME_SLV_3 "tcpdump_pool_slv_3"

enum L2_PROTOCOL
{
    PROTOCOL_IP = 0x0800,
    PROTOCOL_ARP = 0x0806,
    PROTOCOL_RARP = 0x8035,
    PROTOCOL_IPV6 = 0x86DD,
    PROTOCOL_OAM_LACP = 0x8809,
    INVALID_L2_PROTOCOL = 0xFFFF
};

enum L3_PROTOCOL
{
    PROTOCOL_ICMP = 1,
    PROTOCOL_TCP = 6,
    PROTOCOL_UDP = 17,
    INVALID_L3_PROTOCOL = 0xFF
};

enum DUMP_MSG_DIRECTION
{
    DUMP_SEND = 1,
    DUMP_RECV = 2,
    DUMP_SEND_RECV = 3
};

enum DUMP_MSG_TYPE
{
    START_DUMP_REQ,
    STOP_DUMP_REQ,
    TOOL_COM_HBT_REQ,
    START_DUMP_MASTER_REQ,

    DUMP_MSG_TYPE_RSP = 0x00010000,     //65536

    START_DUMP_RSP = START_DUMP_REQ + DUMP_MSG_TYPE_RSP,
    STOP_DUMP_RSP = STOP_DUMP_REQ + DUMP_MSG_TYPE_RSP,
    TOOL_COM_HBT_RSP = TOOL_COM_HBT_REQ + DUMP_MSG_TYPE_RSP,
    START_DUMP_MASTER_RSP = START_DUMP_MASTER_REQ + DUMP_MSG_TYPE_RSP,

    DUMP_MSG_TYPE_INVALID
};

typedef struct _nsfw_tool_hbt
{
    u32 seq;
    i16 task_id;
} nsfw_tool_hbt;

typedef struct _nsfw_tool_dump_msg
{
    u16 op_type;
    i16 task_id;
    u32 task_keep_time;
} nsfw_tool_dump_msg;

typedef struct _dump_msg_info
{
    u32 org_len;
    u16 direction;              // 1:SEND, 2:RECV
    u32 dump_sec;
    u32 dump_usec;
    u32 len;
    nsfw_res res_chk;
    char buf[1];
} dump_msg_info;

typedef struct _dump_timer_info
{
    u32 seq;
    i16 task_id;
    void *interval;
    void *ptimer;
} dump_timer_info;

extern void ntcpdump_loop(void *buf, u32 buf_len, u16 direction,
                          void *eth_addr);
extern void ntcpdump(void *buf, u32 buf_len, u16 direction);
extern int get_dump_status(char *jbuf, int pid);

/*##############for tcpdump######################*/

/*################# HOTFIX Begin ##################*/
#define NSFW_HOTFIX_MODULE "nsfw_hotfix"
#define ALARM_HOTFIX_NAME  "hotfix"

#define MAX_PATCH_PATH_LEN 256
#define MAX_PATCH_VER_LEN  64

#define HOTFIX_STR_ACTV     "activate"
#define HOTFIX_STR_ROLLBACK "rollback"
#define HOTFIX_STR_QUERY    "query"

#define HOTFIX_STR_SUCCESS "success"
#define HOTFIX_STR_FAIL    "fail"

#define HOTFIX_SUCCESS      0
#define HOTFIX_FAIL         1

/* hotfix operation type */
typedef enum
{
    HOTFIX_IDLE,                //invalid value, not use
    HOTFIX_ACTV,                //activate: load & activate & run a patch
    HOTFIX_ROLLBACK,            //rollback: remove a patch
    HOTFIX_QUERY,               //query: query product version
    HOTFIX_MAX
} hotfix_optype;

typedef struct _nsfw_hotfix_msg
{
    u16 rsp_code;
    hotfix_optype optype;
    char patch_path[MAX_PATCH_PATH_LEN];
    char patch_version[MAX_PATCH_VER_LEN];      //product's patch version
} nsfw_hotfix_msg;

typedef struct _hotfix_res
{
    fw_poc_type proc_type;      //process type
    hotfix_optype action;
    int result;
    char patch_version[MAX_PATCH_VER_LEN];      //product's patch version
} hotfix_res;

extern int nsfw_hotfix_module_init(void *param);
/*################# HOTFIX End##################*/
#define NSFW_CONFIG_MODULE "nsfw_config"
#define NSTACK_SHARE_CONFIG "nstack_share_config"

#define CFG_PATH "NSTACK_CONFIG_PATH"
#define CFG_FILE_NAME "nStackConfig.json"
#define MAX_FILE_NAME_LEN 512
#define CFG_BUFFER_LEN 2048
#define MAX_CFG_ITEM 128
#define CFG_ITEM_LENGTH 64

enum NSTACK_BASE_CFG
{
    CFG_BASE_THREAD_NUM = 0,
    CFG_BASE_SOCKET_NUM,
    CFG_BASE_RING_SIZE,
    CFG_BASE_HAL_PORT_NUM,
    CFG_BASE_ARP_STALE_TIME,
    CFG_BASE_ARP_BC_RETRANS_NUM,
    MAX_BASE_CFG
};
/* *INDENT-OFF* */
COMPAT_PROTECT_RETURN (MAX_BASE_CFG, 6)
/* *INDENT-ON* */

enum NSTACK_CUSTOM_CFG
{
    /* mBuf config */
    CFG_MBUF_DATA_SIZE,
    CFG_TX_MBUF_NUM,
    CFG_RX_MBUF_NUM,

    /* memory pool config */
    CFG_MP_TCPSEG_NUM,
    CFG_MP_MSG_NUM,

    /* RING config */
    CFG_HAL_TX_RING_SIZE,
    CFG_HAL_RX_RING_SIZE,
    CFG_MBOX_RING_SIZE,
    CFG_SPL_MAX_ACCEPT_RING_SIZE,

    /* PCB config */
    CFG_TCP_PCB_NUM,
    CFG_UDP_PCB_NUM,
    CFG_RAW_PCB_NUM,

    CFG_ARP_QUEUE_NUM,

    MAX_CUSTOM_CFG
};

enum EN_CFG_SEG
{
    CFG_SEG_BASE = 0,
    CFG_SEG_LOG,
    CFG_SEG_PATH,
    CFG_SEG_PRI,
    CFG_SEG_FOR_MACRO,
    CFG_SEG_PARAM,
    EN_CFG_SEG,
    CFG_SEG_TCP,
    CFG_SEG_SYNC,
    CFG_SEG_RET,
    CFG_SEG_MAX
};

enum EN_CFG_ITEM_TYPE
{
    CFG_ITEM_TYPE_INT = 0,
    CFG_ITEM_TYPE_STRING
};

enum EN_SEG_BASE_ITEM
{
    CFG_ITEM_BASE_SOCKET_NUM = 0,
    CFG_ITEM_BASE_ARP_STALE_TIME,
    CFG_ITEM_BASE_ARP_BC_RETRANS_NUM,
    CFG_ITEM_BASE_APP_SOCKET_NUM,
    CFG_ITEM_BASE_RING_BASE_SIZE,
    CFG_ITEM_BASE_TCP_PCB_NUM,
    CFG_ITEM_BASE_UDP_PCB_NUM,
    CFG_ITEM_BASE_RAW_PCB_NUM,
    CFG_ITEM_BASE_SPL_MAX_RING_SIZE,
    CFG_ITEM_BASE_ARP_QUEUE_NUM,
    CFG_ITEM_BASE_DUMP_MSG_NUM,
    CFG_ITEM_BASE_TX_MBUF_POOL_SIZE,
    CFG_ITEM_BASE_PKT_BURT_NUM,
    CFG_ITEM_BASE_MAX
};

enum EN_SEG_TCP_ITEM
{
    CFG_ITEM_TCP_SYN_REXMIT_INTERVAL_MS = 0,
    CFG_ITEM_TCP_SYN_REXMIT_TIMES,
    CFG_ITEM_TCP_ESTABLISHED_REXMIT_TIMES,
    CFG_ITEM_TCP_MAX
};

enum EN_SEG_THREAD_PRI_ITEM
{
    CFG_ITEM_THREAD_PRI_POLICY = 0,
    CFG_ITEM_THREAD_PRI_PRI,
    CFG_ITEM_THREAD_PRI_MAX
};

enum EN_SEG_FOR_MACRO_ITEM
{
    CFG_ITEM_C10M_SUPPORT = 0,
    CFG_ITEM_FOR_MACRO_MAX
};

enum EN_SEG_MACRO_CUSTOM
{
    CFG_SBR_FD_NETCONN_SIZE = 0,
    CFG_SS_NETCONN_SIZE,
    CFG_DEF_APP_SOCKET_NUM,
    CFG_SOCKET_NUM_PER_THREAD,
    CFG_MAX_SOCKET_NUM,         // same as socket num
    CFG_APP_POOL_NUM,
    CFG_MAX_TCP_HASH_SIZE,
    CFG_DEF_RX_MBUF_POOL_SIZE,  // from POOL_RING_BASE_SIZE
    CFG_DEF_TX_MBUF_POOL_SIZE,
    CFG_MAX_LISTEN_SOCKET_NUM,
    CFG_DEF_SPL_MAX_ACCEPT_RING_SIZE,
    CFG_DEF_TCP_PCB_NUM,
    CFG_DEF_UDP_PCB_NUM,
    CFG_DEF_RAW_PCB_NUM,
    CFG_MAX_EPOLL_NUM,
    CFG_MAX_EPITEM_NUM,
    CFG_MAX_SOCK_FOR_KERNEL,
    CFG_MAX_SOCK_FOR_STACK,
    CFG_DEF_SPL_MAX_RING_SIZE,
    CFG_DEF_HAL_RX_RING_SIZE,
    CFG_DEF_TX_MSG_POOL_SIZE,
    CFG_DEF_MBOX_RING_SIZE,
    CFG_DEF_MPTCP_VERSION,
    CFG_ITEM_MACRO_CUSTOM_MAX
};

typedef void (*custom_check_fn) (void *pitem);

// pack size?
struct cfg_item_info
{
    char *name;
    int type;
    int min_value;
    int max_value;
    int default_value;
    char *default_str;
    custom_check_fn custom_check;
    union
    {
        int value;
        char *pvalue;
    };
};

typedef struct _cfg_module_param
{
    u32 proc_type;
    i32 argc;
    u8 **argv;
} cfg_module_param;

extern u32 g_custom_cfg_items[MAX_CUSTOM_CFG];
extern u32 g_base_cfg_items[MAX_BASE_CFG];
extern u32 g_macro_custom_cfg_items[CFG_ITEM_MACRO_CUSTOM_MAX];
extern struct cfg_item_info g_cfg_item_info[CFG_SEG_MAX][MAX_CFG_ITEM];

#define get_base_cfg(tag) g_base_cfg_items[(tag)]
#define get_custom_cfg(tag) g_custom_cfg_items[(tag)]
#define set_custom_cfg_item(tag, value) g_custom_cfg_items[(tag)] = (value)

/* stackpool config data definition */
#ifndef C10M_SUPPORT
#define C10M_SUPPORT get_cfg_info(CFG_SEG_FOR_MACRO, CFG_ITEM_C10M_SUPPORT)
#endif

#define CFG(item) g_macro_custom_cfg_items[item]
/*
 MAX_SOCKET_NUM: max socket fd number one app can use, it should equal the max socket
 number nstack support(CUR_CFG_SOCKET_NUM)
*/

/* *INDENT-OFF* */
#define DEF_SOCKET_NUM               1024       /* default socket number */
COMPAT_PROTECT_RETURN (DEF_SOCKET_NUM, 1024)
#define MIN_SOCKET_NUM               1024       /* min socket number */
/* *INDENT-ON* */

#define MAX_SOCKET_NUM               8192       /* default: 8K sockets */
#define CUR_CFG_SOCKET_NUM          get_base_cfg(CFG_BASE_SOCKET_NUM)   /* max socket number nstack support */

/* socket num per instance, CUR_CFG_THREAD_NUM should be 2^n */
#define INSTANCE_SOCKET_NUM         (CUR_CFG_SOCKET_NUM/CUR_CFG_THREAD_NUM)

#define DEF_ARP_STACLE_TIME          300        /* default arp stale time: second */
#define MIN_ARP_STACLE_TIME          30 /* min arp stale time: second */
#define MAX_ARP_STACLE_TIME          1200       /* max arp stale time: second */
#define ARP_STALE_TIME               get_base_cfg(CFG_BASE_ARP_STALE_TIME)

#define DEF_ARP_BC_RETRANS_NUM       5  /* default arp broadcast retransmission times */
#define MIN_ARP_BC_RETRANS_NUM       1  /* min arp broadcast retransmission times */
#define MAX_ARP_BC_RETRANS_NUM       20 /* max arp broadcast retransmission times */
#define ARP_BC_RETRANS_NUM           get_base_cfg(CFG_BASE_ARP_BC_RETRANS_NUM)

/* thread number config */
#define DEF_THREAD_NUM               1  /* default stackpool thread number */
#define MIN_THREAD_NUM               1  /* min thread number */
#define MAX_THREAD_NUM               8
#define CUR_CFG_THREAD_NUM           get_base_cfg(CFG_BASE_THREAD_NUM)

/* use GLOBAL_THREAD_INDEX to create socket in apps */
#define GLOBAL_THREAD_INDEX   0

/* hal port number config */
#define DEF_HAL_PORT_NUM             20 /* port number */
/* *INDENT-OFF* */
COMPAT_PROTECT_RETURN (DEF_HAL_PORT_NUM, 20)
/* *INDENT-ON* */
#define MIN_HAL_PORT_NUM             1
#define MAX_HAL_PORT_NUM             255
#define CUR_CFG_HAL_PORT_NUM        get_base_cfg(CFG_BASE_HAL_PORT_NUM)

/* vm number config */
#define MAX_VF_NUM                    4 /* max vf number */
/* *INDENT-OFF* */
COMPAT_PROTECT_RETURN (MAX_VF_NUM, 4)
/* *INDENT-ON* */

/* base ring size config */
#define DEF_RING_BASE_SIZE           2048       /* base ring size */
/* *INDENT-OFF* */
COMPAT_PROTECT_RETURN (DEF_RING_BASE_SIZE, 2048)
/* *INDENT-ON* */
#define MIN_RING_BASE_SIZE           1024
#define MAX_RING_BASE_SIZE           4096
#define POOL_RING_BASE_SIZE         get_base_cfg(CFG_BASE_RING_SIZE)

#define RX_MBUF_MID_THRESHOLD           RX_MBUF_POOL_SIZE/4
#define RX_MBUF_MIN_THRESHOLD           RX_MBUF_POOL_SIZE/16

/* mbuf data size config */
#define DEF_MBUF_DATA_SIZE           2048       /* mbuf data size */
/* *INDENT-OFF* */
COMPAT_PROTECT_RETURN (DEF_MBUF_DATA_SIZE, 2048)
/* *INDENT-ON* */
#define TX_MBUF_MAX_LEN              get_custom_cfg(CFG_MBUF_DATA_SIZE)
/* ptk/task burst config */
#define MAX_PKT_BURST  512
#define MIN_PKT_BURST  1
#define DEF_PKT_BURST           32
/* *INDENT-OFF* */
COMPAT_PROTECT_RETURN (DEF_PKT_BURST, 32)
/* *INDENT-ON* */

/*tcp related param*/
#define SPL_TCP_SYN_RTX_INTVAL     ((u32)get_cfg_info(CFG_SEG_TCP, CFG_ITEM_TCP_SYN_REXMIT_INTERVAL_MS))
#define SPL_TCP_SYNMAXRTX          ((u32)get_cfg_info(CFG_SEG_TCP, CFG_ITEM_TCP_SYN_REXMIT_TIMES))
#define SPL_TCP_MAXRTX             ((u32)get_cfg_info(CFG_SEG_TCP, CFG_ITEM_TCP_ESTABLISHED_REXMIT_TIMES))

/* tx mbuf pool size config */
#define TX_MBUF_POOL_SIZE           get_custom_cfg(CFG_TX_MBUF_NUM)
#define RX_MBUF_POOL_SIZE           get_custom_cfg(CFG_RX_MBUF_NUM)

#define DEF_HAL_TX_RING_SIZE        2048        /* hal tx ring size */
#define HAL_RX_RING_SIZE            get_custom_cfg(CFG_HAL_RX_RING_SIZE)
#define HAL_TX_RING_SIZE            get_custom_cfg(CFG_HAL_TX_RING_SIZE)

/* stackpool recv ring size config */

#define SPL_MAX_RING_SIZE           (u32)get_cfg_info(CFG_SEG_BASE, CFG_ITEM_BASE_SPL_MAX_RING_SIZE)    /* ring size config, used in recv ring(per socket) */

#define MIN_ARP_QUEUE_NUM           300
#define LARGE_ARP_QUEUE_NUM         (512*1024)
#define CUR_ARP_QUEUE_NUM           (u32)get_cfg_info(CFG_SEG_BASE, CFG_ITEM_BASE_ARP_QUEUE_NUM)

#define CUR_CFG_DEF_TCP_PCB_NUM     (u32)get_cfg_info(CFG_SEG_BASE, CFG_ITEM_BASE_TCP_PCB_NUM)
#define CUR_CFG_DEF_UDP_PCB_NUM     (u32)get_cfg_info(CFG_SEG_BASE, CFG_ITEM_BASE_UDP_PCB_NUM)
#define CUR_CFG_DEF_RAW_PCB_NUM     (u32)get_cfg_info(CFG_SEG_BASE, CFG_ITEM_BASE_RAW_PCB_NUM)

/* tcp seg number config */
                                     /* seg num = txbuf num + rxbuf num, and mptcp may double, so set it to txbuf num * 4 */
#define DEF_MEMP_NUM_TCP_SEG         (4 * CFG(CFG_APP_POOL_NUM) * CFG(CFG_DEF_TX_MBUF_POOL_SIZE))

#define TX_MSG_POOL_SIZE             get_custom_cfg(CFG_MP_MSG_NUM)     /* msg number, used by stackpool internal, per thread */

#define MBOX_RING_SIZE               get_custom_cfg(CFG_MBOX_RING_SIZE) /* mbox ring size config, per thread */

#define MIN_DUMP_MSG_NUM (4 * 1024)
#define MAX_DUMP_MSG_NUM (64 * 1024)

/*some problem if CUSOTM_RECV_RING_SIZE more than 4096*/
#define CUSOTM_RECV_RING_SIZE   4096
/* *INDENT-OFF* */
COMPAT_PROTECT_RETURN (CUSOTM_RECV_RING_SIZE, 4096)
/* *INDENT-ON* */

u32 get_cfg_info(int tag, int item);
u32 get_cfg_share_mem_size();

int get_share_cfg_from_mem(void *mem);

void get_default_base_cfg(u32 thread_num);

int set_share_cfg_to_mem(void *mem);

void config_module_init(cfg_module_param * param);

/*##############for netstat######################*/
typedef enum _netstat_protocol_type
{
    NETSTAT_TCP_UDP_CONN,
    NETSTAT_TCP_CONN,
    NETSTAT_UDP_CONN
} netstat_protocol_type;

typedef struct _netstat_send_para
{
    netstat_protocol_type protocol_type;        /*0:all; 1:TCP; 2:UDP */
    unsigned int instance_flag; /*0: all instance; 1:specific instance */
    int instance_id;
} netstat_send_para;

typedef struct _netstat_data_info
{
    unsigned int local_addr;
    unsigned int remote_addr;
    unsigned short local_port;
    unsigned short remote_port;
    unsigned short state;
    unsigned short resv;
} netstat_data_info;

typedef struct _netstat_info
{
    unsigned int pcb_num;
    netstat_data_info data[10240];
} netstat_info;

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif /* __cplusplus */

#endif /* _NSFW_MEM_STAT_API_H  */
