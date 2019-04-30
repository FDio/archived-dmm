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

#ifndef _NSTACK_LOG_H_
#define _NSTACK_LOG_H_
/*==============================================*
 *      include header files                    *
 *----------------------------------------------*/
/* Suppressing _FORTIFY_SOURCE requires compiling with optimization (-O) [-Wcpp]
   _FORTIFY_SOURCE only for optimized release builds.
   This warning can be suppressed, in DMM build we use -O2.
*/
#pragma GCC diagnostic ignored "-Wcpp"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include "types.h"

#include "glog/nstack_glog.ph"
#include "glog/nstack_glog_in.h"

#define NSTACK_FMT_CHECK(fmt_pos) __attribute__((format(printf, fmt_pos, (fmt_pos + 1))))

/* for getVersion response */
#define NSTACK_GETVER_MODULE    "nStack"
/* for Leibniz and CDN */
#define NSTACK_GETVER_NUM        "nStack_N100 V100R003C40B002"

#define NSTACK_GETVER_VERSION    "VPP2.0 " NSTACK_GETVER_NUM
#define NSTACK_GETVER_BUILDTIME "[" __DATE__ "]" "[" __TIME__ "]"
#define NSTACK_VERSION          NSTACK_GETVER_VERSION " (" NSTACK_GETVER_MODULE ") " NSTACK_GETVER_BUILDTIME

#define LOG_TIME_STAMP_LEN 17   // "YYYYMMDDHHMMSS";
#define SPL_MAX_BUF_LEN 2048    // to be remove

#define NSLOG_DEFAULT_FLUSH_TIMEOUT 50
#define REAL_THREAD_SLEEP_TIME 20000
#define REAL_THREAD_RETRY_COUNT 100
/*==============================================*
 *      constants or macros define              *
 *----------------------------------------------*/

#define LOG_INVALID_VALUE 0xFFFF

#define NSTACK_LOG_NAME "/product/gpaas/log/nStack"

typedef struct _log_entry
{
    const char *file;
    u16 line;
    u8 ctrl_bits;
    u8 log_type;
    u16 level;
    u32 last_epoch_dup_cnt;
} log_entry;

typedef struct _log_sup_node
{
    /* data field */
    log_entry entry;
    /* structure indices */
    struct _log_sup_node *rb_parent;
    struct _log_sup_node *rb_left;
    struct _log_sup_node *rb_right;
    bool color;
} log_sup_node;

typedef struct _log_sup_table
{
    log_sup_node *root;
    log_sup_node *nodepool;
    log_sup_node *just_been_freed;
    int count;
    int size;
} log_sup_table;

struct log_init_para
{
    uint32_t run_log_size;
    uint32_t run_log_count;
    char *run_log_path;
    uint32_t mon_log_size;      //master and ctrl both use the parameter to reduce the redundancy
    uint32_t mon_log_count;     //master and ctrl both use the parameter to reduce the redundancy
    char *mon_log_path;         //master and ctrl both use the parameter to reduce the redundancy
};

struct nstack_logs
{
    uint32_t level; /**< Log level. */
    int suppress_off;
    int inited;
    int file_type;
};

#define NS_LOG_STACKPOOL_ON     0x80U
#define NS_LOG_STACKPOOL_TRACE  0x40U
#define NS_LOG_STACKPOOL_STATE  0x20U
#define NS_LOG_STACKPOOL_FRESH  0x10U
#define NS_LOG_STACKPOOL_HALT   0x08U
#define NS_LOG_STACKPOOL_OFF    0x00U

/* LOG_SUP_TABLLE_SIZE_UPPER_LIMIT should be 2^n */
#define LOG_SUP_TABLE_SIZE_UPPER_LIMIT 8192

#define LOG_SUP_TABLE_SIZE_FOR_APP 64
#define LOG_SUP_TABLE_SIZE_FOR_MAIN 1024
#define LOG_SUP_TABLE_SIZE_FOR_MASTER 256
#define LOG_SUP_TABLE_SIZE_FOR_MGR_COM_THREAD 1024
#define LOG_SUP_TABLE_SIZE_FOR_TCPIP_THREAD 1024
#define LOG_SUP_TABLE_SIZE_FOR_PTIMER_THREAD 256

#define NULL_STRING ""
#define MODULE_INIT_FORMAT_STRING "module %s]name=[%s]%s"
#define MODULE_INIT_START  "init"
#define MODULE_INIT_FAIL  "start failed"
#define MODULE_INIT_SUCCESS "start success"

/*log restrain id only canbe used once*/

enum LOG_CTRL_ID
{
    // for socket api
    LOG_CTRL_SEND = 0,
    LOG_CTRL_DO_SEND,
    LOG_CTRL_UDP_SEND,
    LOG_CTRL_RECV,
    LOG_CTRL_DO_RECV,
    LOG_CTRL_SENDMSG,
    LOG_CTRL_RECVMSG,
    LOG_CTRL_READ,
    LOG_CTRL_WRITE,
    LOG_CTRL_DO_WRITE,
    LOG_CTRL_READV,
    LOG_CTRL_WRITEV,
    LOG_CTRL_GETSOCKNAME,
    LOG_CTRL_DO_GETSOCKNAME,
    LOG_CTRL_GETPEERNAME,
    LOG_CTRL_GETSOCKOPT,
    LOG_CTRL_WAIT_NEW_CONN,

    // for nstack service
    LOG_CTRL_RECV_QUEUE_FULL,
    LOG_CTRL_RECV_QUEUE_REST,
    LOG_CTRL_RECV_QUEUE_TIMEOUT,
    LOG_CTRL_L4_RECV_QUEUE_FULL,
    LOG_CTRL_HUGEPAGE_ALLOC_FAIL,
    LOG_CTRL_RX_HUGEPAGE_ALLOC_FAIL,
    LOG_CTRL_PBUF_MEMP_ALLOC_FAIL,
    LOG_CTRL_MEMP_ALLOC_FAIL,
    LOG_CTRL_ICMP_ALLOC_FAIL,
    LOG_CTRL_PBUF_NULL,
    LOG_CTRL_INSTANCE_MEMP_FAIL,
    LOG_CTRL_TCP_MEM_NOT_ENOUGH,
    LOG_CTRL_IPREASS_OVERFLOW,
    LOG_CTRL_DFX_CONN_STAT,
    LOG_CTRL_CHECK_PCI,
    LOG_CTRL_ID_MAX
};

typedef enum _LOG_MODULE
{
    NSOCKET = 1,
    STACKPOOL,
    OPERATION,
    MASTER,
    LOGTCP,
    LOGUDP,
    LOGIP,
    LOGCMP,
    LOGARP,
    LOGRTP,
    LOGHAL,
    LOGDFX,
    LOGFW,
    LOGSBR,
    LOGASYNC,
    MAX_LOG_MODULE
} LOG_MODULE;

enum _LOG_PROCESS
{
    LOG_PRO_NSTACK = 0,
    LOG_PRO_MASTER,
    LOG_PRO_OMC_CTRL,
    LOG_PRO_APP,
    LOG_PRO_INVALID
};

extern struct nstack_logs g_nstack_logs[MAX_LOG_MODULE];

#define NSLOG_CUS     0x20
#define NSLOG_DBG     0x10
#define NSLOG_INF     0x08
#define NSLOG_WAR     0x04
#define NSLOG_ERR     0x02
#define NSLOG_EMG     0x01
#define NSLOG_OFF     0x00
static inline uint32_t nstack_get_log_level(int module)
{
    /* add validity check for path */
    if ((MAX_LOG_MODULE <= module) || (module < 0))
    {
        return -1;              /* clear compile warning */
    }

    return g_nstack_logs[module].level;
}

void write_pre_init_log(bool type);

void set_log_init_para(struct log_init_para *para);

void nstack_setlog_level(int module, uint32_t level);
bool nstack_log_info_check(uint32_t module, uint32_t level);
bool nstack_log_method_check(uint32_t level);
bool check_log_restrain_valid(int id, uint32_t module, uint32_t level);
void nstack_log(uint32_t module, uint32_t level, const char *format, ...);

int nstack_log_init();
void nstack_log_init_app();
void set_log_proc_type(int log_proc_type);

/* timeout in ms, 0 for infinite */
int nstack_log_flush(unsigned long long timeout);

int setlog_level_value(const char *param, const char *value);
int get_str_value(const char *arg);
int check_log_dir_valid(const char *path);
void nstack_segment_error(int s);
void init_log_ctrl_info();
void set_log_ctrl_time(int id, int ctrl_time);

bool check_log_prt_time(int id);
int get_unprt_log_count(int id);
void clr_unprt_log_count(int id);

void get_current_time(char *buf, const int len);

/*****************************************************************************
*   Prototype    : level_stoa
*   Description  : convert stack log level to app log level
*   Input        : unsigned int nstack_level
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
static inline unsigned int level_stoa(unsigned int level)
{
    unsigned int golg_level;
    switch (level)
    {
        case NSLOG_CUS:
            golg_level = GLOG_LEVEL_CUSTOM;
            break;
        case NSLOG_DBG:
            golg_level = GLOG_LEVEL_DEBUG;
            break;
        case NSLOG_INF:
            golg_level = GLOG_LEVEL_INFO;
            break;
        case NSLOG_WAR:
            golg_level = GLOG_LEVEL_WARNING;
            break;
        case NSLOG_ERR:
            golg_level = GLOG_LEVEL_ERROR;
            break;
        case NSLOG_EMG:
            golg_level = GLOG_LEVEL_FATAL;
            break;
        default:
            golg_level = GLOG_LEVEL_BUTT;
            break;
    }
    return golg_level;
}

void set_nstack_log_nonreentry(uint32_t val);
unsigned int get_nstack_log_nonreentry(void);
bool is_log_sup_switched_off(const u8 module);
log_sup_table *get_log_sup_table_addr();
bool update_sup_table_on_logging(const char *file, const u16 line,
                                 const u8 log_type, const u16 level,
                                 log_sup_table * table, u32 * dup_cnt);
log_sup_table *init_sup_table(int table_size);
void save_pre_init_log(uint32_t level, char *fmt, ...);
#define GET_FILE_NAME(name_have_path) strrchr(name_have_path,'/')?strrchr(name_have_path,'/')+1:name_have_path
#ifndef sys_sleep_ns
#define sys_sleep_ns(_s, _ns)\
        {\
            if ((_s) >= 0 && (_ns) >= 0){\
                struct timespec delay, remain;\
                delay.tv_sec=(_s);\
                delay.tv_nsec=(_ns);\
                remain.tv_sec = 0; \
                remain.tv_nsec = 0; \
                while (nanosleep (&delay, &remain) < 0 && errno == EINTR)\
                {\
                    delay = remain;\
                }\
            }\
        }
#endif /* sys_sleep_ns */

/* segregate the dump info */
#define LOG_TYPE(_module, _level)  \
       (((STACKPOOL == _module) && (NSLOG_EMG == _level)) ? GLOG_LEVEL_ERROR : ((OPERATION == _module) ? GLOG_LEVEL_WARNING : GLOG_LEVEL_INFO))

#define log_shooting(_module,_level) \
        ((NULL == g_log_hook_tag.log_hook) ? (nstack_get_log_level(_module) >= _level) : (level_stoa(_level) >= g_log_hook_tag.level))

#define log_not_suppressed(_module, _level) \
        (is_log_sup_switched_off(_module) \
        || !update_sup_table_on_logging(__FILE__, (u16)__LINE__, _module, _level, get_log_sup_table_addr(), NULL))

#define NS_LOGPID(_module,_prestr,_level,fmt, ...) \
{\
    if (log_shooting(_module, _level) && (0 == get_nstack_log_nonreentry()) && nstack_log_info_check(_module, _level))\
    {\
        if (log_not_suppressed(_module, _level))\
        {\
            set_nstack_log_nonreentry(1);\
                 \
                 \
                 \
            if(nstack_log_method_check(_level))\
            {\
                nstack_log(_module, _level, \
                    "%d %s:%d] %d,%s<%s>" fmt "\r\n", (int)syscall(SYS_gettid), GET_FILE_NAME(__FILE__), \
                    __LINE__, getpid(),__func__, _prestr, ##__VA_ARGS__);\
            }\
            else\
            {\
                glog_print(LOG_TYPE(_module,_level),_prestr,level_stoa(_level),-1,GET_FILE_NAME(__FILE__),\
                   __LINE__,__func__,fmt, ##__VA_ARGS__);\
            }\
            set_nstack_log_nonreentry(0);\
        }\
    }\
}

#define NS_LOG_CTRL(_id, _module, _prestr, _level, fmt, ...) \
{\
    if (log_shooting(_module, _level) && (0 == get_nstack_log_nonreentry()) && check_log_restrain_valid(_id, _module, _level))\
    {\
        if (log_not_suppressed(_module, _level))\
        {\
            set_nstack_log_nonreentry(1);\
             \
            if(nstack_log_method_check(_level))\
            {\
                nstack_log(_module, _level, \
                    "%d %s:%d] %d,%s %d<%s>" fmt "\r\n", (int)syscall(SYS_gettid), GET_FILE_NAME(__FILE__), \
                    __LINE__, getpid(),__func__,get_unprt_log_count(_id), _prestr, ##__VA_ARGS__);\
            }\
            else\
            {\
                glog_print(LOG_TYPE(_module,_level),_prestr,level_stoa(_level),get_unprt_log_count(_id),\
                  GET_FILE_NAME(__FILE__),__LINE__,__func__,fmt, ##__VA_ARGS__);\
            }\
            clr_unprt_log_count(_id);\
            set_nstack_log_nonreentry(0);\
        }\
    }\
}

#define NS_LOG_STACKPOOL(dbug,_module,_prestr,_level,fmt, ...) \
{\
    if ((dbug) & NS_LOG_STACKPOOL_ON)\
    {\
        NS_LOGPID(_module,_prestr,_level,fmt,##__VA_ARGS__);\
    }\
}\

#define NS_LOGPID_CHK(_module,_level) log_shooting(_module, _level)

/* hanging up version check log need restrain*/
/* add a asyn log record method*/
#define NS_LOGCUSTOM(_module,_prestr,_level,fmt, ...) \
{\
    if ((0 == get_nstack_log_nonreentry()) && nstack_log_info_check(_module, _level))\
    {\
        set_nstack_log_nonreentry(1);\
        glog_print(GLOG_LEVEL_INFO,_prestr,level_stoa(_level),-1,GET_FILE_NAME(__FILE__),\
               __LINE__,__func__,fmt, ##__VA_ARGS__);\
        set_nstack_log_nonreentry(0);\
    }\
}

/*for every log modules should def marcos below use a sort module name, just like MON means Monitor*/
#define NSMON_LOGINF(fmt, ...) NS_LOGPID(MASTER,"MON",NSLOG_INF,fmt,##__VA_ARGS__)
#define NSMON_LOGDBG(fmt, ...) NS_LOGPID(MASTER,"MON",NSLOG_DBG,fmt,##__VA_ARGS__)
#define NSMON_LOGWAR(fmt, ...) NS_LOGPID(MASTER,"MON",NSLOG_WAR,fmt,##__VA_ARGS__)
#define NSMON_LOGERR(fmt, ...) NS_LOGPID(MASTER,"MON",NSLOG_ERR,fmt,##__VA_ARGS__)

#define NSPOL_LOGINF(debug,fmt, ...) NS_LOG_STACKPOOL(debug,STACKPOOL,"POL",NSLOG_INF,fmt,##__VA_ARGS__)
#define NSPOL_LOGDBG(debug,fmt, ...) NS_LOG_STACKPOOL(debug,STACKPOOL,"POL",NSLOG_DBG,fmt,##__VA_ARGS__)
#define NSPOL_LOGWAR(debug,fmt, ...) NS_LOG_STACKPOOL(debug,STACKPOOL,"POL",NSLOG_WAR,fmt,##__VA_ARGS__)
#define NSPOL_LOGERR(fmt, ...) NS_LOGPID(STACKPOOL,"POL",NSLOG_ERR,fmt,##__VA_ARGS__)
#define NSPOL_LOGEMG(fmt, ...) NS_LOGPID(STACKPOOL,"POL",NSLOG_EMG,fmt,##__VA_ARGS__)
#define NSPOL_LOGCUSINF(fmt, ...) NS_LOGCUSTOM(STACKPOOL,"POL",NSLOG_CUS,fmt,##__VA_ARGS__)

#define NSOPR_LOGINF(fmt, ...) NS_LOGPID(OPERATION,"OPR",NSLOG_INF,fmt,##__VA_ARGS__)
#define NSOPR_LOGDBG(fmt, ...) NS_LOGPID(OPERATION,"OPR",NSLOG_DBG,fmt,##__VA_ARGS__)
#define NSOPR_LOGWAR(fmt, ...) NS_LOGPID(OPERATION,"OPR",NSLOG_WAR,fmt,##__VA_ARGS__)
#define NSOPR_LOGERR(fmt, ...) NS_LOGPID(OPERATION,"orchestration",NSLOG_ERR,fmt,##__VA_ARGS__)

#define NSSOC_LOGINF(fmt, ...) NS_LOGPID(NSOCKET,"SOC",NSLOG_INF,fmt,##__VA_ARGS__)
#define NSSOC_LOGDBG(fmt, ...) NS_LOGPID(NSOCKET,"SOC",NSLOG_DBG,fmt,##__VA_ARGS__)
#define NSSOC_LOGWAR(fmt, ...) NS_LOGPID(NSOCKET,"SOC",NSLOG_WAR,fmt,##__VA_ARGS__)
#define NSSOC_LOGERR(fmt, ...) NS_LOGPID(NSOCKET,"SOC",NSLOG_ERR,fmt,##__VA_ARGS__)

#define NSSBR_LOGINF(fmt, ...) NS_LOGPID(LOGSBR,"SBR",NSLOG_INF,fmt,##__VA_ARGS__)
#define NSSBR_LOGDBG(fmt, ...) NS_LOGPID(LOGSBR,"SBR",NSLOG_DBG,fmt,##__VA_ARGS__)
#define NSSBR_LOGWAR(fmt, ...) NS_LOGPID(LOGSBR,"SBR",NSLOG_WAR,fmt,##__VA_ARGS__)
#define NSSBR_LOGERR(fmt, ...) NS_LOGPID(LOGSBR,"SBR",NSLOG_ERR,fmt,##__VA_ARGS__)

#define NSRTP_LOGINF(fmt, ...) NS_LOGPID(LOGRTP, "RTP",NSLOG_INF,fmt,##__VA_ARGS__)
#define NSRTP_LOGDBG(fmt, ...) NS_LOGPID(LOGRTP, "RTP",NSLOG_DBG,fmt,##__VA_ARGS__)
#define NSRTP_LOGWAR(fmt, ...) NS_LOGPID(LOGRTP, "RTP",NSLOG_WAR,fmt,##__VA_ARGS__)
#define NSRTP_LOGERR(fmt, ...) NS_LOGPID(LOGRTP, "RTP",NSLOG_ERR,fmt,##__VA_ARGS__)

#define NSTCP_LOGINF(fmt, ...) NS_LOGPID(LOGTCP,"TCP",NSLOG_INF,fmt,##__VA_ARGS__)
#define NSTCP_LOGDBG(fmt, ...) NS_LOGPID(LOGTCP,"TCP",NSLOG_DBG,fmt,##__VA_ARGS__)
#define NSTCP_LOGWAR(fmt, ...) NS_LOGPID(LOGTCP,"TCP",NSLOG_WAR,fmt,##__VA_ARGS__)
#define NSTCP_LOGERR(fmt, ...) NS_LOGPID(LOGTCP,"TCP",NSLOG_ERR,fmt,##__VA_ARGS__)

#define NSIP_LOGINF(fmt, ...) NS_LOGPID(LOGIP,"IP",NSLOG_INF,fmt,##__VA_ARGS__)
#define NSIP_LOGDBG(fmt, ...) NS_LOGPID(LOGIP,"IP",NSLOG_DBG,fmt,##__VA_ARGS__)
#define NSIP_LOGWAR(fmt, ...) NS_LOGPID(LOGIP,"IP",NSLOG_WAR,fmt,##__VA_ARGS__)
#define NSIP_LOGERR(fmt, ...) NS_LOGPID(LOGIP,"IP",NSLOG_ERR,fmt,##__VA_ARGS__)
#define NSIP_LOGDBG_OPEN !(NS_LOGPID_CHK(LOGIP,NSLOG_DBG))

#define NSUDP_LOGINF(fmt, ...) NS_LOGPID(LOGUDP,"UDP",NSLOG_INF,fmt,##__VA_ARGS__)
#define NSUDP_LOGDBG(fmt, ...) NS_LOGPID(LOGUDP,"UDP",NSLOG_DBG,fmt,##__VA_ARGS__)
#define NSUDP_LOGWAR(fmt, ...) NS_LOGPID(LOGUDP,"UDP",NSLOG_WAR,fmt,##__VA_ARGS__)
#define NSUDP_LOGERR(fmt, ...) NS_LOGPID(LOGUDP,"UDP",NSLOG_ERR,fmt,##__VA_ARGS__)

#define NSHAL_LOGINF(fmt, ...) NS_LOGPID(LOGHAL,"HAL",NSLOG_INF,fmt,##__VA_ARGS__)
#define NSHAL_LOGDBG(fmt, ...) NS_LOGPID(LOGHAL,"HAL",NSLOG_DBG,fmt,##__VA_ARGS__)
#define NSHAL_LOGWAR(fmt, ...) NS_LOGPID(LOGHAL,"HAL",NSLOG_WAR,fmt,##__VA_ARGS__)
#define NSHAL_LOGERR(fmt, ...) NS_LOGPID(LOGHAL,"HAL",NSLOG_ERR,fmt,##__VA_ARGS__)

#define NSARP_LOGINF(fmt, ...) NS_LOGPID(LOGARP,"ARP",NSLOG_INF,fmt,##__VA_ARGS__)
#define NSARP_LOGDBG(fmt, ...) NS_LOGPID(LOGARP,"ARP",NSLOG_DBG,fmt,##__VA_ARGS__)
#define NSARP_LOGWAR(fmt, ...) NS_LOGPID(LOGARP,"ARP",NSLOG_WAR,fmt,##__VA_ARGS__)
#define NSARP_LOGERR(fmt, ...) NS_LOGPID(LOGARP,"ARP",NSLOG_ERR,fmt,##__VA_ARGS__)

#define NSDFX_LOGINF(fmt, ...) NS_LOGPID(LOGDFX,"DFX",NSLOG_INF,fmt,##__VA_ARGS__)
#define NSDFX_LOGDBG(fmt, ...) NS_LOGPID(LOGDFX,"DFX",NSLOG_DBG,fmt,##__VA_ARGS__)
#define NSDFX_LOGWAR(fmt, ...) NS_LOGPID(LOGDFX,"DFX",NSLOG_WAR,fmt,##__VA_ARGS__)
#define NSDFX_LOGERR(fmt, ...) NS_LOGPID(LOGDFX,"DFX",NSLOG_ERR,fmt,##__VA_ARGS__)

#define NSFW_LOGINF(fmt, ...) NS_LOGPID(LOGFW,"FW",NSLOG_INF,fmt,##__VA_ARGS__)
#define NSFW_LOGDBG(fmt, ...) NS_LOGPID(LOGFW,"FW",NSLOG_DBG,fmt,##__VA_ARGS__)
#define NSFW_LOGERR(fmt, ...) NS_LOGPID(LOGFW,"FW",NSLOG_ERR,fmt,##__VA_ARGS__)
#define NSFW_LOGWAR(fmt, ...) NS_LOGPID(LOGFW,"FW",NSLOG_WAR,fmt,##__VA_ARGS__)

#define NSAM_LOGINF(fmt, ...) NS_LOGPID(LOGFW,"AM",NSLOG_INF,fmt,##__VA_ARGS__)
#define NSAM_LOGDBG(fmt, ...) NS_LOGPID(LOGFW,"AM",NSLOG_DBG,fmt,##__VA_ARGS__)
#define NSAM_LOGERR(fmt, ...) NS_LOGPID(LOGFW,"AM",NSLOG_ERR,fmt,##__VA_ARGS__)
#define NSAM_LOGWAR(fmt, ...) NS_LOGPID(LOGFW,"AM",NSLOG_WAR,fmt,##__VA_ARGS__)

// TODO: HotFix need remove
/* for HotFix module */
#define NSHF_LOGINF(fmt, ...) NS_LOGPID(LOGFW,"HF",NSLOG_INF,fmt,##__VA_ARGS__)
#define NSHF_LOGDBG(fmt, ...) NS_LOGPID(LOGFW,"HF",NSLOG_DBG,fmt,##__VA_ARGS__)
#define NSHF_LOGERR(fmt, ...) NS_LOGPID(LOGFW,"HF",NSLOG_ERR,fmt,##__VA_ARGS__)
#define NSHF_LOGWAR(fmt, ...) NS_LOGPID(LOGFW,"HF",NSLOG_WAR,fmt,##__VA_ARGS__)

#define INIT_LOG_ASSEM(log_module,_prestr,_level, init_module , function, errString, errValue, status) \
     \
    if ((LOG_INVALID_VALUE <= errValue) && (1 == sizeof(errString))) \
    { \
        NS_LOGPID(log_module,_prestr, _level,MODULE_INIT_FORMAT_STRING, (char*)status, init_module, function ); \
    } \
    else if (LOG_INVALID_VALUE <= errValue)\
    { \
        NS_LOGPID(log_module,_prestr, _level,MODULE_INIT_FORMAT_STRING",err_string=%s", (char*)status, init_module, function, errString ); \
    } \
    else if (1 == sizeof(errString))\
    { \
        NS_LOGPID(log_module,_prestr, _level,MODULE_INIT_FORMAT_STRING",err_value=%d", (char*)status, init_module, function, errValue ); \
    } \
    else \
    { \
        NS_LOGPID(log_module,_prestr, _level,MODULE_INIT_FORMAT_STRING",err_string=%s,err_value=%d", (char*)status, init_module, function, errString, errValue ); \
    } \


#define INITPOL_LOGINF(init_module_name, function, err_string, err_value, status) \
    \
    INIT_LOG_ASSEM(STACKPOOL,"POL",NSLOG_INF,init_module_name , function, err_string, err_value, status)\


#define INITPOL_LOGERR(init_module_name, function, err_string, err_value, status) \
    \
    INIT_LOG_ASSEM(STACKPOOL,"POL",NSLOG_ERR,init_module_name , function, err_string, err_value, status)\


#define INITTCP_LOGINF(init_module_name , function, err_string, err_value, status) \
    \
    INIT_LOG_ASSEM(LOGTCP,"TCP",NSLOG_INF,init_module_name , function, err_string, err_value, status)\


#define INITTCP_LOGERR(init_module_name , function, err_string, err_value, status) \
    \
    INIT_LOG_ASSEM(LOGTCP,"TCP",NSLOG_ERR,init_module_name , function, err_string, err_value, status)\


#define INITMON_LOGERR(init_module_name , function, err_string, err_value, status) \
    \
    INIT_LOG_ASSEM(MASTER,"MON",NSLOG_ERR,init_module_name , function, err_string, err_value, status)\


/*add the init log info*/
#define INITSOC_LOGERR(init_module_name , function, err_string, err_value, status) \
    INIT_LOG_ASSEM(NSOCKET,"SOC",NSLOG_ERR,init_module_name , function, err_string, err_value, status)

#define NSPOL_DUMP_LOGINF(fmt, ...) NSPOL_LOGINF(0x80, fmt, ##__VA_ARGS__)
#define NSPOL_DUMP_LOGDBG(fmt, ...) NSPOL_LOGDBG(0x80, fmt, ##__VA_ARGS__)
#define NSPOL_DUMP_LOGERR(fmt, ...) NSPOL_LOGERR(fmt, ##__VA_ARGS__)
#define NSPOL_DUMP_LOGWAR(fmt, ...) NSPOL_LOGWAR(0x80, fmt, ##__VA_ARGS__)

/*==============================================*
 *      project-wide global variables           *
 *----------------------------------------------*/

#define fuzzy_uint32(src) ((src) & 0x0000ffff)
#define fuzzy_uint64(src) ((src) & 0x00000000ffffffff)

/*==============================================*
 *      routines' or functions' implementations *
 *----------------------------------------------*/
/* *INDENT-OFF* */
#ifndef FREE_IF_NOT_NULL
#define FREE_IF_NOT_NULL(mem) \
    if (mem) \
    {\
        free(mem); \
        mem = NULL; \
    }
#endif
/* *INDENT-ON* */
//#define CPU_CYCLES
#ifdef CPU_CYCLES
static __inline__ unsigned long long nstack_rdtsc(void)
{
    unsigned hi, lo;
    __asm__ __volatile__("rdtsc":"=a"(lo), "=d"(hi));
    return ((unsigned long long) lo) | (((unsigned long long) hi) << 32);
}

#define CPUB(name) \
unsigned long long start##name = 0;\
unsigned long long stop##name = 0;\
static unsigned long long total##name = 0;\
static unsigned long long total_cout##name = 0;\
start##name = nstack_rdtsc();

#define CPUE(name) \
stop##name = nstack_rdtsc();\
total##name += (stop##name - start##name);\
if(++total_cout##name == 1000000)\
{\
	NSSOC_LOGINF(#name" cpu %llu-------\n", total##name / total_cout##name);\
	total##name = 0;\
	total_cout##name = 0;\
}
#else
#define CPUB(name)
#define CPUE(name)
#endif

#endif
