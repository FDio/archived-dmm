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
#include "nstack_log_base.h"
#include "nstack_log_async.h"
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include "nstack_securec.h"
#include "nsfw_maintain_api.h"
#include <pthread.h>

/*==============================================*
 *      constants or macros define              *
 *----------------------------------------------*/

#define FILE_NAME_LEN 256

int g_l4_dump_enable = 0;

__thread unsigned int nstack_log_nonreentry = 0;
//ctrl log switch just for ctrl now
bool ctrl_log_switch = FALSE;

/*==============================================*
 *      project-wide global variables           *
 *----------------------------------------------*/
struct nstack_logs g_nstack_logs[MAX_LOG_MODULE] = { {0, 0, 0, 0}, {0xFFFF, 0, 0, 0} }; /* Clear compile warning */

struct log_init_para g_log_init_para =
    { 50, 10, NSTACK_LOG_NAME, 10, 10, NSTACK_LOG_NAME };

static int g_my_pro_type = LOG_PRO_INVALID;

#define DEFAULT_LOG_CTR_TIME 5
static struct log_ctrl_info g_log_ctrl_info[LOG_CTRL_ID_MAX];

//better put in the struct for file_type
bool log_asyn_inited = FALSE;

/*==============================================*
 *      routines' or functions' implementations *
 *----------------------------------------------*/

void write_pre_init_log(bool type)
{
    int i = 0;
    int ret = -1;
    int count = get_pre_init_log_count();
    size_t size = MAX_PRE_INIT_LOG_COUNT * sizeof(struct pre_init_info);
    unsigned int level = 0;

    struct pre_init_info *pre_buf = (struct pre_init_info *) malloc(size);      /*malloc() can be used */
    if (!pre_buf)
    {
        NSPOL_LOGERR("malloc fail]count=%d", count);
        return;
    }

    ret = memset_s(pre_buf, size, 0, size);
    if (EOK != ret)
    {
        NSPOL_LOGERR("memset_s fail]ret=%d,count=%d", ret, count);
        free(pre_buf);          /*free() can be used */
        return;
    }

    ret = get_pre_init_log_buffer(pre_buf, MAX_PRE_INIT_LOG_COUNT);
    if (ret < 0)
    {
        NSPOL_LOGERR("get the init log fail]ret=%d,count=%d", ret, count);
        free(pre_buf);          /*free() can be used */
        return;
    }

    for (; i < count; i++)
    {
        level = pre_buf[i].level;
        if (type && (level >= NSLOG_INF))
        {
            continue;
        }

        switch (level)
        {
            case NSLOG_ERR:
                NSPOL_LOGERR("pre init log: %s", pre_buf[i].log_buffer);
                break;
            case NSLOG_WAR:
                NSPOL_LOGWAR(NS_LOG_STACKPOOL_ON, "pre init log: %s",
                             pre_buf[i].log_buffer);
                break;
            case NSLOG_INF:
                NSPOL_LOGINF(NS_LOG_STACKPOOL_ON, "pre init log: %s",
                             pre_buf[i].log_buffer);
                break;
            case NSLOG_DBG:
                NSPOL_LOGDBG(NS_LOG_STACKPOOL_ON, "pre init log: %s",
                             pre_buf[i].log_buffer);
                break;
            default:
                break;
        }
    }

    free(pre_buf);              /*free() can be used */
    return;
}

void get_current_time(char *buf, const int len)
{
    if (NULL == buf || len <= 0)
    {
        return;
    }

    int retVal;
    time_t cur_tick;
    struct tm cur_time;

    (void) time(&cur_tick);     /*time() can be used */
    if (NULL == localtime_r(&cur_tick, &cur_time))
    {
        return;
    }

    // from man page of localtime_r:
    // tm_year   The number of years since 1900.
    // tm_mon    The number of months since January, in the range 0 to 11.
    /* There are some unsafe function ,need to be replace with safe function */
    retVal = snprintf_s(buf, len, len - 1, "%04d%02d%02d%02d%02d%02d",
                        cur_time.tm_year + 1900, cur_time.tm_mon + 1,
                        cur_time.tm_mday, cur_time.tm_hour, cur_time.tm_min,
                        cur_time.tm_sec);
    if (-1 == retVal)
    {
        return;
    }
    buf[len - 1] = 0;
}

void nstack_setlog_level(int module, uint32_t level)
{
    if (MAX_LOG_MODULE <= module || module < 0)
    {
        return;
    }
    g_nstack_logs[module].level = level;
    /* log suppression switched off when level set to DBG */
    g_nstack_logs[module].suppress_off = (NSLOG_DBG == level) ? 1 : 0;
}

bool nstack_log_info_check(uint32_t module, uint32_t level)
{
    if ((MAX_LOG_MODULE <= module) || !nstack_log_level_valid(level))
    {
        return FALSE;
    }

    /* no need compare module ,which is done ahead */
    if ((LOG_PRO_INVALID == g_my_pro_type) || (FALSE != ctrl_log_switch))
    {
        return FALSE;
    }

    return TRUE;

}

/*****************************************************************************
*   Prototype    : nstack_log_method_check
*   Description  : log print method choice, process main, master, nStackCtrl use
*                  domain socket to log, app and segment error use orginal method.
*   Input        : uint32_t level
*                  ...
*   Output       : None
*   Return Value : bool
*   Calls        :
*   Called By    :
*****************************************************************************/
bool nstack_log_method_check(uint32_t level)
{
    if (LOG_PRO_APP <= g_my_pro_type)
    {
        return FALSE;
    }

    //for segment error log
    if (level == NSLOG_EMG)
    {
        return FALSE;
    }

    if (!log_asyn_inited)
    {
        return FALSE;
    }

    return TRUE;
}

NSTACK_STATIC int get_file_type(uint32_t module)
{
    return g_nstack_logs[module].file_type;
}

/*****************************************************************************
*   Prototype    : nstack_log
*   Description  : log print
*   Input        : uint32_t module
*                  const char *format
*                  ...
*   Output       : None
*   Return Value : None
*   Calls        :
*   Called By    :
*****************************************************************************/
NSTACK_FMT_CHECK(3)
     void nstack_log(uint32_t module, uint32_t level, const char *format, ...)
{
    va_list ap;
    int ret;
    char pre_buf[PRE_INIT_LOG_LENGTH] = { 0 };
    char buf[MAX_BUFFER_LEN] = { 0 };
    char format_buf[MAX_BUFFER_LEN];
    format_buf[sizeof(format_buf) - 1] = 0;
    int file_type = 0;

    if (NULL == format)
    {
        return;
    }

    ret = nstack_log_get_prefix(level, pre_buf, sizeof(pre_buf));
    if (ret < 0)
    {
        return;
    }

    ret = sprintf_s(format_buf, sizeof(format_buf), "%s %s", pre_buf, format);
    if (-1 == ret)
    {
        return;
    }

    va_start(ap, format);       /*no need to check return */
    ret = vsprintf_s(buf, sizeof(buf), format_buf, ap);
    if (-1 == ret)
    {
        va_end(ap);
        return;
    }
    va_end(ap);

    buf[sizeof(buf) - 1] = '\0';

    //get the file type
    if (MAX_LOG_MODULE <= module)
    {
        return;                 //something wrong, but can't print log here
    }
    file_type = get_file_type(module);

    // send the buf and write to client fd
    (void) nstack_log_client_send(file_type, buf, ret);

    return;
}

NSTACK_STATIC inline void init_operation_log_para()
{
    g_nstack_logs[OPERATION].file_type = LOG_TYPE_OPERATION;
}

NSTACK_STATIC inline void init_nstack_log_para()
{
    int i = 0;

    /* change to glog functions,no need file type control */
    (void) glogLevelSet(GLOG_LEVEL_DEBUG);
    glogBufLevelSet(GLOG_LEVEL_WARNING);
    for (; i < GLOG_LEVEL_BUTT; i++)
        glogSetLogSymlink(i, "");
    glogDir(g_log_init_para.run_log_path);
    nstack_log_count_set(g_log_init_para.run_log_count);
    glogMaxLogSizeSet(g_log_init_para.run_log_size);
    glogSetLogFilenameExtension(STACKPOOL_LOG_NAME);
    glogFlushLogSecsSet(FLUSH_TIME);

    /* Fix nstack_log_init file type */
    for (i = 0; i < MAX_LOG_MODULE; i++)
    {
        if (i == OPERATION)
        {
            continue;
        }

        g_nstack_logs[i].file_type = LOG_TYPE_NSTACK;
    }

    init_operation_log_para();
}

NSTACK_STATIC inline void init_ctrl_log_para()
{
    int i = 0;

    /* change to glog functions,no need file type control */
    /*  omc_ctrl single log file should be 10M [Start] */
    (void) glogLevelSet(GLOG_LEVEL_DEBUG);
    glogBufLevelSet(GLOG_LEVEL_WARNING);
    for (; i < GLOG_LEVEL_BUTT; i++)
        glogSetLogSymlink(i, "");
    glogDir(g_log_init_para.mon_log_path);
    nstack_log_count_set(g_log_init_para.mon_log_count);
    glogMaxLogSizeSet(g_log_init_para.mon_log_size);
    glogSetLogFilenameExtension(OMC_CTRL_LOG_NAME);
    glogFlushLogSecsSet(FLUSH_TIME);

    for (i = 0; i < MAX_LOG_MODULE; i++)
    {
        g_nstack_logs[i].file_type = LOG_TYPE_CTRL;
    }
}

NSTACK_STATIC inline void init_master_log_para()
{
    int i = 0;

    /* change to glog functions,no need file type control */
    (void) glogLevelSet(GLOG_LEVEL_DEBUG);
    glogBufLevelSet(GLOG_LEVEL_WARNING);
    for (; i < GLOG_LEVEL_BUTT; i++)
        glogSetLogSymlink(i, "");
    glogDir(g_log_init_para.mon_log_path);
    nstack_log_count_set(g_log_init_para.mon_log_count);
    glogMaxLogSizeSet(g_log_init_para.mon_log_size);
    glogSetLogFilenameExtension(MASTER_LOG_NAME);
    glogFlushLogSecsSet(FLUSH_TIME);

    for (i = 0; i < MAX_LOG_MODULE; i++)
    {
        g_nstack_logs[i].file_type = LOG_TYPE_MASTER;
    }
}

/*****************************************************************************
*   Prototype    : nstack_log_init
*   Description  : called by environment-specific log init function
*   Input        : None
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int nstack_log_init()
{
    char *pst_temp = NULL;
    uint32_t log_level = NSLOG_INF;
    int proc_type = g_my_pro_type;
    int ret_client = 0;
    int ret_server = 0;
    bool type = FALSE;

    pst_temp = getenv("NSTACK_LOG_ON"); /*getenv() can be used */

    if (pst_temp)
    {
        if (strcmp(pst_temp, "INF") == 0)
        {
            log_level = NSLOG_INF;
        }
        else if (strcmp(pst_temp, "DBG") == 0)
        {
            log_level = NSLOG_DBG;
        }
        else if (strcmp(pst_temp, "WAR") == 0)
        {
            log_level = NSLOG_WAR;
        }
        else if (strcmp(pst_temp, "ERR") == 0)
        {
            log_level = NSLOG_ERR;
        }
        else if (strcmp(pst_temp, "EMG") == 0)
        {
            log_level = NSLOG_EMG;
        }
        else
        {
            log_level = NSLOG_ERR;
        }

    }
    else
    {
        log_level = NSLOG_INF;
    }

    int i = 0;
    for (i = 0; i < MAX_LOG_MODULE; i++)
    {
        nstack_setlog_level(i, log_level);
    }

    if (log_level <= NSLOG_WAR)
    {
        /*MONITR log level must set to larger than warning */
        nstack_setlog_level(MASTER, NSLOG_WAR);
    }

    /* monitr and nstack write the same file, it will cause synchronize problem */
    switch (proc_type)
    {
        case LOG_PRO_NSTACK:
            glogInit("NSTACK");
            init_nstack_log_para();
            break;
        case LOG_PRO_OMC_CTRL:
            glogInit("CTRL");
            init_ctrl_log_para();
            type = TRUE;
            break;
        case LOG_PRO_MASTER:
            glogInit("MASTER");
            init_master_log_para();
            break;
        default:
            return 0;
    }

    init_log_ctrl_info();

    // this is for monitr to check whether log has beed inited
    g_nstack_logs[NSOCKET].inited = 1;

    /* init the asyn log method for */
    ret_server = nstack_log_server_init(proc_type);

    ret_client = nstack_log_client_init(proc_type);

    /* if async log init fail,
     *   use synchron log method and record it.*/

    if ((ret_client == 0) && (ret_server == 0))
    {
        log_asyn_inited = TRUE;
    }
    else
    {
        NSPOL_LOGWAR(NS_LOG_STACKPOOL_ON,
                     "async log module init fail, use synchron log");
    }

    NSPOL_LOGINF(NS_LOG_STACKPOOL_ON, "daemon-stack_version=%s",
                 NSTACK_VERSION);
    NSPOL_LOGINF(NS_LOG_STACKPOOL_ON,
                 "ret_client=%d,ret_server=%d,log_asyn_inited=%d",
                 ret_client, ret_server, log_asyn_inited);

    /* omc log restrain */
    write_pre_init_log(type);

    return 0;
}

/* nStack Log print */
/*****************************************************************************
*   Prototype    : get_str_value
*   Description  : get int value
*   Input        : const char *arg
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int get_str_value(const char *arg)
{
    char *parsing_end;
    int iValue = 0;
    int oldErrno = errno;

    if (arg == NULL)
    {
        return -1;
    }
    errno = 0;
    iValue = (int) strtol(arg, &parsing_end, 0);
    if (errno || (!parsing_end) || parsing_end[0] != 0)
    {
        iValue = -1;
    }
    errno = oldErrno;
    return iValue;
}

/*****************************************************************************
*   Prototype    : setlog_level_value
*   Description  : proc log level config
*   Input        : const char *param
*                  const char *value
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int setlog_level_value(const char *param, const char *value)
{
    int i = 0;
    int module = 0;
    int logLevel = 0;
    module = get_str_value(param);
    if ((module < 0) || (MAX_LOG_MODULE <= module))
    {
        NSOPR_LOGERR("input module error]param=%s,module=%d", param, module);
        return 1;
    }
    if (strcmp(value, LOG_LEVEL_ERR) == 0)
    {
        logLevel = NSLOG_ERR;
    }
    else if (strcmp(value, LOG_LEVEL_WAR) == 0)
    {
        logLevel = NSLOG_WAR;
    }
    else if (strcmp(value, LOG_LEVEL_DBG) == 0)
    {
        logLevel = NSLOG_DBG;
    }
    else if (strcmp(value, LOG_LEVEL_INF) == 0)
    {
        logLevel = NSLOG_INF;
    }
    else if (strcmp(value, LOG_LEVEL_EMG) == 0)
    {
        logLevel = NSLOG_EMG;
    }
    else
    {
        NSOPR_LOGERR("input log level error!");
        return 1;
    }

    NSOPR_LOGINF("set module log with level]module=%d,logLevel=0x%x", module,
                 logLevel);

    if (module > 0)
    {
        nstack_setlog_level(module, logLevel);
        return 0;
    }

    if (0 == module)
    {
        for (i = 0; i < MAX_LOG_MODULE; i++)
        {
            nstack_setlog_level(i, logLevel);
        }
    }

    return 0;
}

/*****************************************************************************
*   Prototype    : check_log_dir_valid
*   Description  : check the log dir valid or not
*   Input        : const char *arg
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int check_log_dir_valid(const char *path)
{
    size_t length;
    struct stat statbuf;
    if (NULL == path)
    {
        return -1;
    }

    length = strlen(path) + 1;
    if ((length <= 1) || (length > FILE_NAME_LEN))
    {
        return -1;
    }

    /* only write permission is legal */
    if ((0 != access(path, W_OK)))
    {
        /* if path can access, use env path */
        return -1;
    }

    if ((0 == lstat(path, &statbuf)) && S_ISDIR(statbuf.st_mode))
    {
        return 0;

    }
    else
    {
        return -1;
    }
}

/*****************************************************************************
*   Prototype    : get_app_env_log_path
*   Description  : called by environment-specific log init function
*   Input        : app_file_path, a char pointer to store the log path
*   Input        : app_file_size, the app_file_path size
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
int get_app_env_log_path(char *app_file_path, unsigned int app_file_size)
{
    char *pst_app_log_path_flag = NULL;
    char *pst_app_log_path_string = NULL;
    int log_to_file = 0;
    int ret = -1;
    char *app_dir = NULL;

    if ((NULL == app_file_path) || (0 == app_file_size))
    {
        return 0;
    }

    pst_app_log_path_flag = getenv("NSTACK_LOG_FILE_FLAG");     /* getenv() can be used */

    if (pst_app_log_path_flag && strcmp(pst_app_log_path_flag, "1") == 0)
    {
        /* if set enviroment variable to 1,then output to file */
        log_to_file = 1;
    }
    else
    {
        /*  if enviroment variable is not equal 1 or don't set this enviroment variable ,output to STDOUT */
        return 0;
    }

    /* add the realpath and dir check */
    /* APP LOG can be set by user */
    pst_app_log_path_string = getenv("NSTACK_APP_LOG_PATH");    /* getenv() can be used */
    if ((NULL == pst_app_log_path_string)
        || (strlen(pst_app_log_path_string) > FILE_NAME_LEN - 1))
    {
        goto app_default;
    }

    app_dir = realpath(pst_app_log_path_string, NULL);
    if (check_log_dir_valid(pst_app_log_path_string) < 0)
    {
        goto app_default;
    }
    ret = strcpy_s(app_file_path, app_file_size, app_dir);
    if (EOK != ret)
    {
        log_to_file = 0;
    }

    free(app_dir);
    return log_to_file;

  app_default:

    if ((0 == access(APP_LOG_PATH, W_OK)))
    {
        ret = strcpy_s(app_file_path, app_file_size, APP_LOG_PATH);
        if (EOK != ret)
        {
            log_to_file = 0;
        }
    }
    else
    {
        log_to_file = 0;
    }

    if (NULL != app_dir)
    {
        free(app_dir);
    }

    return log_to_file;

}

/*****************************************************************************
*   Prototype    : nstack_log_init_app
*   Description  : called by environment-specific log init function
*   Input        : None
*   Output       : None
*   Return Value : int
*   Calls        :
*   Called By    :
*****************************************************************************/
void nstack_log_init_app()
{
    char *pc_temp = NULL;
    uint32_t log_level = NSLOG_ERR;
    int i = 0;
    int file_flag = 0;
    char app_log_path[FILE_NAME_LEN] = { 0 };

    /* log alread initialized, just return */
    if (LOG_PRO_INVALID != g_my_pro_type)
    {
        return;
    }

    /* Add app log hook module init */
    nstack_log_hook_init();

    if (0 != g_nstack_logs[NSOCKET].inited)
    {
        return;
    }

    glogInit("APP");

    pc_temp = getenv("NSTACK_LOG_ON");  /*getenv() can be used */

    if (pc_temp)
    {
        if (strcmp(pc_temp, "INF") == 0)
        {
            log_level = NSLOG_INF;
        }
        else if (strcmp(pc_temp, "DBG") == 0)
        {
            log_level = NSLOG_DBG;
        }
        else if (strcmp(pc_temp, "WAR") == 0)
        {
            log_level = NSLOG_WAR;
        }
        else if (strcmp(pc_temp, "ERR") == 0)
        {
            log_level = NSLOG_ERR;
        }
        else if (strcmp(pc_temp, "EMG") == 0)
        {
            log_level = NSLOG_EMG;
        }
        else
        {
            log_level = NSLOG_ERR;
        }

    }
    else
    {
        log_level = NSLOG_ERR;
    }

    /* socket interface APP called include both stackpool and nstack module! */
    nstack_setlog_level(STACKPOOL, log_level);
    nstack_setlog_level(NSOCKET, log_level);
    nstack_setlog_level(LOGRTP, log_level);
    nstack_setlog_level(LOGDFX, log_level);
    nstack_setlog_level(LOGFW, log_level);
    nstack_setlog_level(LOGHAL, log_level);
    nstack_setlog_level(LOGSBR, log_level);

    file_flag = get_app_env_log_path(app_log_path, FILE_NAME_LEN);
    if ((1 == file_flag) && (strlen(app_log_path) > 0))
    {
        /* change to glog functions,no need file type control */
        glogDir(app_log_path);
        glogBufLevelSet(GLOG_LEVEL_WARNING);
        (void) glogLevelSet(GLOG_LEVEL_DEBUG);
        for (i = 0; i < GLOG_LEVEL_BUTT; i++)
            glogSetLogSymlink(i, "");
        nstack_log_count_set(APP_LOG_COUNT);
        glogMaxLogSizeSet(APP_LOG_SIZE);
        glogSetLogFilenameExtension(APP_LOG_NAME);
        glogFlushLogSecsSet(FLUSH_TIME);
    }
    else
    {
        glogToStderrSet(1);
    }

    for (i = 0; i < MAX_LOG_MODULE; i++)
    {
        g_nstack_logs[i].file_type = LOG_TYPE_APP;
    }

    init_log_ctrl_info();

    g_my_pro_type = LOG_PRO_APP;
    SetGlogCtrlOpt(TRUE);

    NSPOL_LOGCUSINF("app_nStack_version=%s", NSTACK_VERSION);
    return;
}

void nstack_segment_error(int s)
{
#define BACKTRACE_SIZ 20

    void *array[BACKTRACE_SIZ];
    int size;
    int i;
    char **strings = NULL;

    /*if set, flush the log immediately */
    glogFlushLogFiles(GLOG_LEVEL_DEBUG);

    size = backtrace(array, BACKTRACE_SIZ);
    NSPOL_LOGEMG
        ("------------------DUMP_BACKTRACE[%d]--------------------------------\n",
         size);

    /*easy to view signal in  separate log file */
    NSPOL_LOGEMG("Received signal s=%d", s);

    for (i = 0; i < size; i++)
    {
        NSPOL_LOGEMG("[%d]:%p\n", i, array[i]);
    }

    strings = backtrace_symbols(array, size);
    if (NULL == strings)
    {
        return;
    }
    for (i = 0; i < size; i++)
    {
        NSPOL_LOGEMG("[%d]:%s\n", i, strings[i]);
    }

    NSPOL_LOGEMG
        ("-------------------------------------------------------------------\n");
    free(strings);              /*free() can be used */

}

void set_log_init_para(struct log_init_para *para)
{
    if (NULL == para)
    {
        return;
    }

    if (EOK !=
        memcpy_s(&g_log_init_para, sizeof(struct log_init_para), para,
                 sizeof(struct log_init_para)))
    {
        return;
    }
}

/* control log printed counts */
static inline void update_log_prt_time(struct timespec *cur_time,
                                       struct timespec *log_prt_time)
{
    log_prt_time->tv_sec = cur_time->tv_sec;
    log_prt_time->tv_nsec = cur_time->tv_nsec;
}

bool check_log_prt_time(int id)
{
    struct timespec cur_time;
    struct timespec *log_prt_time = NULL;

    if (id >= LOG_CTRL_ID_MAX || id < 0)
    {
        return FALSE;
    }

    (void) clock_gettime(CLOCK_MONOTONIC, &cur_time);
    log_prt_time = &g_log_ctrl_info[id].last_log_time;

    if (cur_time.tv_sec - log_prt_time->tv_sec >=
        g_log_ctrl_info[id].expire_time)
    {
        /*first log need print, Begin */
        set_log_ctrl_time(id, DEFAULT_LOG_CTR_TIME);
        update_log_prt_time(&cur_time, log_prt_time);
        return TRUE;
    }

    g_log_ctrl_info[id].unprint_count++;
    return FALSE;
}

/*****************************************************************************
*   Prototype    : check_log_restrain_valid
*   Description  : check if the log if valid and ctrl restrain time expire.
*   Input        : int id
*                : uint32_t module,
*                : uint32_t level
*                  ...
*   Output       : None
*   Return Value : bool
*   Calls        :
*   Called By    :
*****************************************************************************/
bool check_log_restrain_valid(int id, uint32_t module, uint32_t level)
{
    if (nstack_log_info_check(module, level) && check_log_prt_time(id))
    {
        return TRUE;
    }

    return FALSE;
}

int get_unprt_log_count(int id)
{
    return g_log_ctrl_info[id].unprint_count;
}

void clr_unprt_log_count(int id)
{
    g_log_ctrl_info[id].unprint_count = 0;
}

void set_log_ctrl_time(int id, int ctrl_time)
{
    if (id >= LOG_CTRL_ID_MAX || id < 0)
    {
        return;
    }

    if (ctrl_time <= 0)
    {
        return;
    }

    g_log_ctrl_info[id].expire_time = ctrl_time;
}

void init_log_ctrl_info()
{
    int i = 0;
    for (; i < LOG_CTRL_ID_MAX; i++)
    {
        /*first log need print */
        g_log_ctrl_info[i].expire_time = 0;
        g_log_ctrl_info[i].unprint_count = 0;
        g_log_ctrl_info[i].last_log_time.tv_sec = 0;
        g_log_ctrl_info[i].last_log_time.tv_nsec = 0;
    }

    // for every socket api, need different log id

    // for nstack inner
}

void set_log_proc_type(int log_proc_type)
{
    g_my_pro_type = log_proc_type;
}

int nstack_log_flush(unsigned long long timeout)
{
    if (LOG_PRO_APP <= g_my_pro_type)
    {
        glogFlushLogFiles(GLOG_LEVEL_DEBUG);
        return 0;
    }

    if (log_asyn_inited)
    {
        return nstack_log_server_flush(g_my_pro_type, timeout);
    }
    else
    {
        return -1;
    }
}

void set_nstack_log_nonreentry(uint32_t val)
{
    nstack_log_nonreentry = val;
}

unsigned int get_nstack_log_nonreentry(void)
{
    return nstack_log_nonreentry;
}
