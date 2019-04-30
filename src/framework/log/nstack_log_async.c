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

#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "types.h"
#include "nstack_securec.h"
#include "nsfw_base_linux_api.h"
#include "nstack_log_async.h"

#include <signal.h>
#include <syscall.h>

/*sockaddr_un.sun_path is an array of 108 bytes*/
#define UNIX_SOCK_MAX_PATH_LEN 108
#define MAX_CONN_NUM 5
#define MAX_LOG_RECV_BUF         0x34000*2
#define ASYNLOG_THREAD_NAME "nstk_log_asyn"

NSTACK_STATIC char nstack_sock_running[UNIX_SOCK_MAX_PATH_LEN + 1];
NSTACK_STATIC char nstack_sock_operation[UNIX_SOCK_MAX_PATH_LEN + 1];
NSTACK_STATIC char nstack_sock_master[UNIX_SOCK_MAX_PATH_LEN + 1];
NSTACK_STATIC char nstack_sock_ctrl[UNIX_SOCK_MAX_PATH_LEN + 1];
NSTACK_STATIC char nstack_sock_dir[UNIX_SOCK_MAX_PATH_LEN + 1];

int g_nstack_log_client_fd[MAX_LOG_TYPE] = { -1, -1, -1, -1, -1 };
int g_nstack_log_server_fd[MAX_LOG_TYPE] = { -1, -1, -1, -1, -1 };

#define NSTACK_LOG_SER_STATE_RUNNING 0
#define NSTACK_LOG_SER_STATE_FLUSHING 1

#define NSTACK_LOG_SER_FLUSH_SIG '\5'

NSTACK_STATIC int g_nstack_log_server_state[MAX_LOG_TYPE] = { NSTACK_LOG_SER_STATE_RUNNING };   /*can be used */

static int pre_init_log_count = 0;
static struct pre_init_info pre_init_log[MAX_PRE_INIT_LOG_COUNT] =
    { {0, ""} };
__thread unsigned int pre_log_nonreentry = 0;
extern bool log_asyn_inited;

/*****************************************************************************
*   Prototype    : nstack_log_sock_set
*   Description  : set the sockfd state, for example O_NONBLOCK and so on,
*   Input        : int sock: fd.
*                : int type: module type.
*                  ...
*   Output       : None
*   Return Value : 0 means success, -1 means fail.
*   Calls        :
*   Called By    :
*****************************************************************************/
NSTACK_STATIC inline int nstack_log_sock_set(int sock, int type)
{
    int flags;

    if (type < 0)
    {
        return -1;
    }

    flags = nsfw_base_fcntl(sock, F_GETFD, 0);
    if (flags < 0)
    {
        return -1;
    }

    flags |= type;

    if (nsfw_base_fcntl(sock, F_SETFD, flags) < 0)
    {
        return -1;
    }

    return 0;
}

/*****************************************************************************
*   Prototype    : unlink_log_servername
*   Description  : unlink the servername
*   Input        : int log_type:
*                  ...
*   Output       : None
*   Return Value : void
*   Calls        :
*   Called By    :
*****************************************************************************/

void unlink_log_servername(int log_type)
{
    switch (log_type)
    {
        case LOG_TYPE_NSTACK:
            unlink(nstack_sock_running);
            break;
        case LOG_TYPE_OPERATION:
            unlink(nstack_sock_operation);
            break;
        case LOG_TYPE_MASTER:
            unlink(nstack_sock_master);
            break;
        case LOG_TYPE_CTRL:
            unlink(nstack_sock_ctrl);
            break;
        default:
            break;
    }
    return;

}

/*****************************************************************************
*   Prototype    : nstack_log_sock_path
*   Description  : init the nstack log domain socket path which use to handle
*                  the log with a thread of long connect
*   Input        : int proc_type
*                  ...
*   Output       : static varible store
*   Return Value : >=0 means success, -1 means fail.
*   Calls        :
*   Called By    :
*****************************************************************************/
NSTACK_STATIC int nstack_log_sock_path(int proc_type)
{
    char *directory = "/var/run";
    const char *home_dir = getenv("HOME");      /*can be used */
    bool env_path = FALSE;
    int ret = -1;
    int val = -1;
    int val_opera = -1;
    pid_t pid = getpid();

    if (getuid() != 0 && home_dir != NULL)
    {
        directory = realpath(home_dir, NULL);
        if (!directory)
        {
            save_pre_init_log(NSLOG_ERR, "directory is NULL]errno=%d", errno);
            return -1;
        }
        env_path = TRUE;
    }

    if (EOK != (ret = strcpy_s(nstack_sock_dir, UNIX_SOCK_MAX_PATH_LEN, directory)))    /* check return value with EOK */
    {
        save_pre_init_log(NSLOG_ERR, "strcpy_s fail]ret=%d", ret);
        goto err_init;
    }

    /*modify 'destMax' and return value check */
    if (EOK !=
        (ret =
         strcat_s(nstack_sock_dir, sizeof(nstack_sock_dir), "/ip_module")))
    {
        save_pre_init_log(NSLOG_ERR, "strcat_s fail]ret=%d", ret);
        goto err_init;
    }

    switch (proc_type)
    {
        case LOG_PRO_NSTACK:
            val =
                sprintf_s(nstack_sock_running, UNIX_SOCK_MAX_PATH_LEN,
                          "%s/%s_%d", nstack_sock_dir, "nStackMainRunLog",
                          pid);
            val_opera =
                sprintf_s(nstack_sock_operation, UNIX_SOCK_MAX_PATH_LEN,
                          "%s/%s_%d", nstack_sock_dir, "nStackMainOpeLog",
                          pid);
            if (val_opera < 0)
            {
                save_pre_init_log(NSLOG_ERR, "sprintf_s fail]val_opera=%d",
                                  val_opera);
                ret = -1;
                goto err_init;
            }
            break;
        case LOG_PRO_MASTER:
            val =
                sprintf_s(nstack_sock_master, UNIX_SOCK_MAX_PATH_LEN,
                          "%s/%s_%d", nstack_sock_dir, "nStackMasterLog",
                          pid);
            break;
        case LOG_PRO_OMC_CTRL:
            // nStackCtrl don't add pid, as it may exit before unlink which may leave a useless file in ip_module directory.
            // this will cause losing some log sometime, but it's ok.
            val =
                sprintf_s(nstack_sock_ctrl, UNIX_SOCK_MAX_PATH_LEN, "%s/%s",
                          nstack_sock_dir, "nStackCtrlLog");
            break;
        default:
            save_pre_init_log(NSLOG_ERR, "process invalid]proc_type=%d",
                              proc_type);
            ret = -1;
            goto err_init;
    }

    if ((val < 0))
    {
        save_pre_init_log(NSLOG_ERR, "sprintf_s fail]proc_type=%d,val=%d",
                          proc_type, val);
        ret = -1;
        goto err_init;
    }

    ret = 0;

  err_init:

    if (env_path == TRUE)
    {
        free(directory);
    }
    return ret;
}

/*****************************************************************************
*   Prototype    : nstack_log_sock_listen
*   Description  : create the nstack log domain socket, bind the share domain file,
*                  listen the client connect, for server side.
*   Input        : const char *servername, file name for the domain
*                  ...
*   Output       : listen fd
*   Return Value : >=0 means success, -1 means fail.
*   Calls        :
*   Called By    :
*****************************************************************************/
NSTACK_STATIC int nstack_log_sock_listen(const char *servername)
{
    int fd, ret;
    unsigned int len;
    struct stat st;
    struct sockaddr_un un;
    int opt = 1;

    if ((ret = stat(nstack_sock_dir, &st)) != 0)
    {
        save_pre_init_log(NSLOG_ERR,
                          "stat get file info fail]ret=%d,nstack_sock_dir=%s",
                          ret, nstack_sock_dir);
        return -1;
    }

    if ((fd = nsfw_base_socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        save_pre_init_log(NSLOG_ERR, "create socket fail]fd=%d,errno=%d", fd,
                          errno);
        return -1;
    }

    if ((ret =
         nsfw_base_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt,
                              sizeof(opt))) < 0)
    {
        save_pre_init_log(NSLOG_ERR, "set socket reuse fail]ret=%d,errno=%d",
                          ret, errno);
        goto listen_err;
    }

    unlink(servername);         /* in case it already exists */

    ret = memset_s(&un, sizeof(un), 0, sizeof(un));
    if (EOK != ret)
    {
        save_pre_init_log(NSLOG_ERR, "memset_s fail]ret=%d", ret);
        goto listen_err;
    }

    un.sun_family = AF_UNIX;
    ret = strcpy_s(un.sun_path, sizeof(un.sun_path), servername);
    if (EOK != ret)
    {
        save_pre_init_log(NSLOG_ERR, "strcpy_s fail]ret=%d", ret);
        goto listen_err;
    }

    len =
        (unsigned int) (offsetof(struct sockaddr_un, sun_path) +
                        strlen(servername));

    if ((ret = nsfw_base_bind(fd, (struct sockaddr *) &un, len)) < 0)
    {
        save_pre_init_log(NSLOG_ERR,
                          "bind domain socket fail]ret=%d,errno=%d", ret,
                          errno);
        goto listen_err;
    }

    if ((ret = nsfw_base_listen(fd, MAX_CONN_NUM)) < 0)
    {
        save_pre_init_log(NSLOG_ERR, "listen fail]ret=%d,errno=%d", ret,
                          errno);
        goto listen_err;
    }

    return fd;

  listen_err:

    (void) nsfw_base_close(fd);

    return -1;

}

/*****************************************************************************
*   Prototype    : nstack_log_fd_to_type
*   Description  : traverse the fd from fds to get the fd num, it returns
*                  the file type, which matches the fd.
*   Input        : int *fds
*                : int fd
*                  ...
*   Output       : fd
*   Return Value : >=0 means success, -1 means fail.
*   Calls        :
*   Called By    :
*****************************************************************************/
NSTACK_STATIC inline int nstack_log_fd_to_type(const int *fds, int fd)
{
    int i;
    for (i = 0; i <= LOG_TYPE_CTRL; i++)
    {
        if (fd == fds[i])
        {
            return i;
        }
    }
    return -1;
}

/*****************************************************************************
*   Prototype    : nstack_log_signal_handler
*   Description  : syn Leibniz issue, the signal interrupt 34, the log collect
*                  thread create early as process signal handle too late.
*   Input        : None
*                  ...
*   Output       : None
*   Return Value : 0 success, -1 false
*   Calls        :
*   Called By    :
*****************************************************************************/
int nstack_log_signal_handler()
{
    sigset_t waitset, oset;
    int s = -1;

    if (0 != sigemptyset(&waitset))
    {
        NS_PTHREADLOG(LOG_TYPE_UNRECOGNIZED, NSLOG_ERR, "sigemptyset fail");
        return -1;
    }

    if (0 != sigaddset(&waitset, SIGRTMIN))
    {
        NS_PTHREADLOG(LOG_TYPE_UNRECOGNIZED, NSLOG_ERR,
                      "sigaddset fail]SIGRTMIN");
        return -1;
    }

    if (0 != sigaddset(&waitset, SIGRTMIN + 2))
    {
        NS_PTHREADLOG(LOG_TYPE_UNRECOGNIZED, NSLOG_ERR,
                      "sigaddset fail]SIGRTMIN+2");
        return -1;
    }

    if ((s = pthread_sigmask(SIG_BLOCK, &waitset, &oset)) != 0)
    {
        NS_PTHREADLOG(LOG_TYPE_UNRECOGNIZED, NSLOG_ERR,
                      "pthread_sigmask fail]s=%d", s);
        return -1;
    }

    return 0;

}

#define ASYNC_MAXEVENTS 20
NSTACK_STATIC int nstack_log_server_prepare(int proc_type,
                                            struct epoll_event *ev,
                                            int *epfd,
                                            struct epoll_event *events)
{
    int ret;
    int listen_fd;

    /* thread signal mask handle */
    if (nstack_log_signal_handler() < 0)
    {
        NS_PTHREADLOG(LOG_TYPE_UNRECOGNIZED, NSLOG_ERR,
                      "signal handle fail]proc_type=%d", proc_type);
        return -1;
    }

    /* init the array */
    ret =
        memset_s(events, sizeof(struct epoll_event) * ASYNC_MAXEVENTS, 0,
                 sizeof(struct epoll_event) * ASYNC_MAXEVENTS);
    if (EOK != ret)
    {
        NS_PTHREADLOG(LOG_TYPE_UNRECOGNIZED, NSLOG_ERR,
                      "memset_s fail]ret=%d,proc_type=%d", ret, proc_type);
        return -1;
    }

    // create ep fd, the max scope of epoll is 256
    *epfd = nsfw_base_epoll_create(256);
    if (*epfd < 0)
    {
        NS_PTHREADLOG(LOG_TYPE_UNRECOGNIZED, NSLOG_ERR,
                      "create epoll fail]epfd=%d,proc_type=%d,errno=%d",
                      *epfd, proc_type, errno);
        return -1;
    }

    int i;
    for (i = 0; i <= LOG_TYPE_CTRL; i++)
    {
        if ((listen_fd = g_nstack_log_server_fd[i]) <= 0)
        {
            continue;
        }
        ev->data.fd = listen_fd;
        ev->events = EPOLLIN;

        // add server listen fd to epoll
        if ((ret =
             nsfw_base_epoll_ctl(*epfd, EPOLL_CTL_ADD, listen_fd, ev)) < 0)
        {
            NS_PTHREADLOG(LOG_TYPE_UNRECOGNIZED, NSLOG_ERR,
                          "epoll ctl add fail]ret=%d,epfd=%d,listen_fd=%d,errno=%d",
                          ret, *epfd, listen_fd, errno);
            return -1;
        }
    }
    return 0;

}

NSTACK_STATIC int nstack_log_server_recv_old(int *accepted_fd,
                                             struct epoll_event *event)
{
    int sockfd;
    int log_type;
    //one log content 2048 enough.
    char buffer[MAX_BUFFER_LEN];
    ssize_t num;

    log_type = nstack_log_fd_to_type(accepted_fd, event->data.fd);
    /*log_type has been protected */
    if ((log_type >= 0) && (log_type < MAX_LOG_TYPE))
    {
        if ((sockfd = event->data.fd) < 0)
        {
            NS_PTHREADLOG(log_type, NSLOG_WAR,
                          "accept fd invalid]sockfd=%d,log_type=%d", sockfd,
                          log_type);
            return -1;
        }

        /* change 3th param from 'sizeof(buffer)' to 'sizeof(buffer)-1', make room for '\0' terminated */
        if ((num =
             nsfw_base_recv(sockfd, buffer, sizeof(buffer) - 1, 0)) <= 0)
        {
            if (num == 0 || (errno != EAGAIN && errno != EINTR))
            {
                //if server close, client side will recv EPIPE
                NS_PTHREADLOG(log_type, NSLOG_ERR,
                              "recv the msg fail]sockfd=%d,num=%ld,log_type=%d,errno=%d",
                              sockfd, num, log_type, errno);
                (void) nsfw_base_close(accepted_fd[log_type]);
                accepted_fd[log_type] = -1;
            }
            return -1;
        }

        int offset = 0;
        int j;
        if (g_nstack_log_server_state[log_type] ==
            NSTACK_LOG_SER_STATE_FLUSHING)
        {
            for (j = 0; j < num; j++)
            {
                if (buffer[j] == NSTACK_LOG_SER_FLUSH_SIG)
                {
                    buffer[j] = '\0';
                    glog_print_buffer(log_type, buffer, j);
                    glogFlushLogFiles(GLOG_LEVEL_DEBUG);

                    (void) (__sync_bool_compare_and_swap
                            (&g_nstack_log_server_state[log_type],
                             NSTACK_LOG_SER_STATE_FLUSHING,
                             NSTACK_LOG_SER_STATE_RUNNING));

                    offset = j + 1;
                    break;
                }
            }
        }

        /* make buffer '\0' terminated. glog_print_buffer() need a '\0' terminated string, or it will coredump!!! */
        buffer[num] = '\0';

        if (offset < num)
        {
            // write file
            glog_print_buffer(log_type, buffer + offset, num - offset);
        }

        return -1;
    }

    return 0;
}

NSTACK_STATIC int nstack_log_server_accept_new(int *accepted_fd,
                                               struct epoll_event *ev,
                                               int epfd,
                                               struct epoll_event *event)
{
    int ret;
    int log_type;

    log_type = nstack_log_fd_to_type(g_nstack_log_server_fd, event->data.fd);
    /*log_type has been protected */
    if ((log_type >= 0) && (log_type < MAX_LOG_TYPE))
    {
        struct sockaddr_un un_cli;
        socklen_t clilen = sizeof(un_cli);
        accepted_fd[log_type] =
            nsfw_base_accept(event->data.fd, (struct sockaddr *) &un_cli,
                             &clilen);
        if (accepted_fd[log_type] < 0)
        {
            NS_PTHREADLOG(log_type, NSLOG_WAR,
                          "accept the socket fail]accepted_fd[%d]=%d,errno=%d",
                          log_type, accepted_fd[log_type], errno);
            return -1;
        }
        ev->data.fd = accepted_fd[log_type];

        int size, size_len;
        size = MAX_LOG_RECV_BUF;
        size_len = sizeof(size);
        if ((ret =
             nsfw_base_setsockopt(accepted_fd[log_type], SOL_SOCKET,
                                  SO_RCVBUF, (void *) &size,
                                  (socklen_t) size_len)) < 0)
        {
            NS_PTHREADLOG(log_type, NSLOG_WAR,
                          "set the socket sendbuf fail]accepted_fd[%d]=%d,ret=%d,errno=%d",
                          log_type, accepted_fd[log_type], ret, errno);
            (void) nsfw_base_close(accepted_fd[log_type]);
            accepted_fd[log_type] = -1;
            return -1;
        }

        //set the non_blocking mode.
        if ((ret =
             nstack_log_sock_set(accepted_fd[log_type], O_NONBLOCK)) < 0)
        {
            NS_PTHREADLOG(log_type, NSLOG_WAR,
                          "set the socket non_blocking fail]accepted_fd[%d]=%d,ret=%d",
                          log_type, accepted_fd[log_type], ret);
            (void) nsfw_base_close(accepted_fd[log_type]);
            accepted_fd[log_type] = -1;
            return -1;
        }

        if ((ret =
             nsfw_base_epoll_ctl(epfd, EPOLL_CTL_ADD, accepted_fd[log_type],
                                 ev)) < 0)
        {
            NS_PTHREADLOG(log_type, NSLOG_WAR,
                          "add epoll fail]accepted_fd[%d]=%d,ret=%d,errno=%d",
                          log_type, accepted_fd[log_type], ret, errno);
            (void) nsfw_base_close(accepted_fd[log_type]);
            accepted_fd[log_type] = -1;
            return -1;
        }

        if ((ret =
             nsfw_base_epoll_ctl(epfd, EPOLL_CTL_DEL, event->data.fd,
                                 NULL)) < 0)
        {
            NS_PTHREADLOG(log_type, NSLOG_WAR,
                          "delete the epoll listen fail]event->data.fd=%d,ret=%d,errno=%d",
                          event->data.fd, ret, errno);
        }

        // remove server listening fd and servername as no use then
        (void) nsfw_base_close(event->data.fd);

        unlink_log_servername(log_type);

    }

    return 0;
}

/*****************************************************************************
*   Prototype    : nstack_log_server_process
*   Description  : init the nstack log domain socket for server side, and create
*                  a thread to wait the client conect or data come.
*   Input        : int proc_type
*                  ...
*   Output       : None
*   Return Value : void*
*   Calls        :
*   Called By    :
*****************************************************************************/
void *nstack_log_server_process(void *args)
{
    int epfd;
    struct epoll_event ev, events[ASYNC_MAXEVENTS];
    int accepted_fd[MAX_LOG_TYPE] = { -1, -1, -1, -1, -1 };
    int proc_type = (int) (u64) args;

    if (0 != nstack_log_server_prepare(proc_type, &ev, &epfd, events))
    {
        /* err msg has been printed */
        return ((void *) 0);
    }

    while (1)
    {
        int i;
        int nfds = nsfw_base_epoll_wait(epfd, events, ASYNC_MAXEVENTS, -1);

        for (i = 0; i < nfds; i++)
        {
            /*Notes: it listen the epoll all of the process, cannot save the log by save_pre_init_log
             *       for the log recv module*/
            if (0 != nstack_log_server_recv_old(accepted_fd, &events[i]))
                continue;

            /*Notes: accept the client fd */
            if (0 !=
                nstack_log_server_accept_new(accepted_fd, &ev, epfd,
                                             &events[i]))
                continue;
        }

    }

    return ((void *) 0);        /*can be used, should never get here */
}

/*****************************************************************************
*   Prototype    : nstack_log_sock_conn
*   Description  : create the nstack log domain socket, and connect the server,
*                  for client side.
*   Input        : const char *servername, file name for the domain
*                  ...
*   Output       : fd
*   Return Value : >=0 means success, -1 means fail.
*   Calls        :
*   Called By    :
*****************************************************************************/
NSTACK_STATIC int nstack_log_sock_conn(const char *servername)
{
    int fd = -1;
    unsigned int len;
    struct sockaddr_un un;
    int opt = 1;
    int ret = -1;
    int size = MAX_LOG_RECV_BUF;
    size_t size_len;
    size_len = sizeof(size);

    if (NULL == servername)
    {
        save_pre_init_log(NSLOG_ERR,
                          "invalid input parameter]servername=NULL");
        return -1;
    }

    //create a UNIX domain stream socket and it is non blocking
    if ((fd = nsfw_base_socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0)   /*can be used */
    {
        save_pre_init_log(NSLOG_ERR,
                          "client create the domain socket fail]fd=%d,errno=%d",
                          fd, errno);
        return -1;
    }

    if ((ret =
         nsfw_base_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt,
                              sizeof(opt))) < 0)
    {
        save_pre_init_log(NSLOG_ERR,
                          "client set domain socket reuse fail]fd=%d,ret=%d,errno=%d",
                          fd, ret, errno);
        goto connect_err;
    }

    if ((ret =
         nsfw_base_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void *) &size,
                              (socklen_t) size_len)) < 0)
    {
        save_pre_init_log(NSLOG_ERR,
                          "client set domain socket sendbuf fail]fd=%d,ret=%d,errno=%d",
                          fd, ret, errno);
        goto connect_err;
    }

    ret = memset_s(&un, sizeof(un), 0, sizeof(un));
    if (EOK != ret)
    {
        save_pre_init_log(NSLOG_ERR, "memset_s fail]ret=%d", ret);
        goto connect_err;
    }
    un.sun_family = AF_UNIX;
    if (strlen(servername) > UNIX_SOCK_MAX_PATH_LEN)
    {
        save_pre_init_log(NSLOG_ERR,
                          "servername string is %d bigger than %d",
                          strlen(servername), UNIX_SOCK_MAX_PATH_LEN);
        goto connect_err;
    }
    ret = strcpy_s(un.sun_path, sizeof(un.sun_path), servername);
    if (EOK != ret)
    {
        save_pre_init_log(NSLOG_ERR, "strcpy_s fail]ret=%d", ret);
        goto connect_err;
    }

    len =
        (unsigned int) (offsetof(struct sockaddr_un, sun_path) +
                        strlen(servername));

    //connect the server
    if ((ret = nsfw_base_connect(fd, (struct sockaddr *) &un, len)) < 0)
    {
        save_pre_init_log(NSLOG_ERR,
                          "client connect the server fail]ret=%d,errno=%d",
                          ret, errno);
        goto connect_err;
    }

    return fd;

  connect_err:

    (void) nsfw_base_close(fd);

    return -1;

}

/*****************************************************************************
*   Prototype    : nstack_log_server_init
*   Description  : init the nstack log domain socket for server side, and create
*                  a thread to wait the client conect or data come.
*   Input        : int proc_type
*                  ...
*   Output       : None
*   Return Value : 0 means success, -1 means fail.
*   Calls        :
*   Called By    :
*****************************************************************************/
int nstack_log_server_init(int proc_type)
{
    int ret = -1;
    int listen_fd = -1;
    int listen_fd_opera = -1;

    if ((ret = nstack_log_sock_path(proc_type)) < 0)
    {
        save_pre_init_log(NSLOG_ERR, "asyn server get path fail]ret=%d", ret);
        return -1;
    }

    switch (proc_type)
    {
        case LOG_PRO_NSTACK:
            g_nstack_log_server_state[LOG_TYPE_NSTACK] =
                NSTACK_LOG_SER_STATE_RUNNING;
            g_nstack_log_server_state[LOG_TYPE_OPERATION] =
                NSTACK_LOG_SER_STATE_RUNNING;
            listen_fd = nstack_log_sock_listen(nstack_sock_running);
            g_nstack_log_server_fd[LOG_TYPE_NSTACK] = listen_fd;
            listen_fd_opera = nstack_log_sock_listen(nstack_sock_operation);
            g_nstack_log_server_fd[LOG_TYPE_OPERATION] = listen_fd_opera;
            if (listen_fd_opera < 0)
            {
                save_pre_init_log(NSLOG_ERR,
                                  "asyn server operation fd listen fail]listen_fd_opera=%d",
                                  listen_fd_opera);
                return -1;
            }
            break;
        case LOG_PRO_MASTER:
            g_nstack_log_server_state[LOG_TYPE_MASTER] =
                NSTACK_LOG_SER_STATE_RUNNING;
            listen_fd = nstack_log_sock_listen(nstack_sock_master);
            g_nstack_log_server_fd[LOG_TYPE_MASTER] = listen_fd;
            break;
        case LOG_PRO_OMC_CTRL:
            g_nstack_log_server_state[LOG_TYPE_CTRL] =
                NSTACK_LOG_SER_STATE_RUNNING;
            listen_fd = nstack_log_sock_listen(nstack_sock_ctrl);
            g_nstack_log_server_fd[LOG_TYPE_CTRL] = listen_fd;
            break;
        default:
            save_pre_init_log(NSLOG_ERR, "process invalid]proc_type=%d",
                              proc_type);
            return -1;
    }

    if (listen_fd < 0)
    {
        save_pre_init_log(NSLOG_ERR, "asyn server listen fail]listen_fd=%d",
                          listen_fd);
        return -1;
    }

    pthread_t t;
    if ((ret =
         pthread_create(&t, NULL, nstack_log_server_process,
                        (void *) (u64) proc_type)) != 0)
    {
        save_pre_init_log(NSLOG_ERR, "asyn server create thread fail]ret=%d",
                          ret);
        return -1;
    }

    /* thread name string should smaller than 16 bytes */

    ret = pthread_setname_np(t, ASYNLOG_THREAD_NAME);
    if (ret != 0)
    {
        save_pre_init_log(NSLOG_WAR,
                          "asyn server set thread name fail, use process name]ret=%d",
                          ret);
    }
    else
    {
        save_pre_init_log(NSLOG_INF,
                          "asyn server set thread name success]thread name=%s",
                          ASYNLOG_THREAD_NAME);
    }

    if (proc_type == LOG_PRO_NSTACK)
    {
        save_pre_init_log(NSLOG_INF,
                          "asyn server init success]listen_fd=%d,listen_fd_opera=%d",
                          listen_fd, listen_fd_opera);
    }
    else
    {
        save_pre_init_log(NSLOG_INF, "asyn server init success]listen_fd=%d",
                          listen_fd);
    }

    return 0;
}

#define NSTACK_LOG_SEND_FLUSH_SIG(fd, ret) \
do \
{\
    if (fd > 0) \
    { \
        ret = nsfw_base_send(fd, "\5" /* NSTACK_LOG_SER_FLUSH_SIG */, 1, MSG_NOSIGNAL); \
    } else { \
        ret = -1; \
    }\
} while(0)

#ifndef MAX_U64_NUM
#define MAX_U64_NUM ((unsigned long long)0xffffffffffffffff)
#endif

NSTACK_STATIC int nstack_log_current_time2msec(unsigned long long *msec)
{
    struct timespec tout;
    if (0 != clock_gettime(CLOCK_MONOTONIC, &tout))
    {
        return -1;
    }

    if (MAX_U64_NUM / 1000 < (unsigned long long) tout.tv_sec)
    {
        return -1;
    }
    unsigned long long sec2msec = 1000 * tout.tv_sec;
    unsigned long long nsec2msec =
        (unsigned long long) tout.tv_nsec / 1000000;

    if (MAX_U64_NUM - sec2msec < nsec2msec)
    {
        return -1;
    }

    *msec = sec2msec + nsec2msec;
    return 0;
}

int nstack_log_server_flush(int proc_type, unsigned long long timeout)
{
    int i = 0;
    unsigned long long start = 0;
    unsigned long long end = 0;
    int flushed = 0;
    int ret = 0;

    switch (proc_type)
    {
        case LOG_PRO_NSTACK:
            g_nstack_log_server_state[LOG_TYPE_NSTACK] =
                NSTACK_LOG_SER_STATE_FLUSHING;
            g_nstack_log_server_state[LOG_TYPE_OPERATION] =
                NSTACK_LOG_SER_STATE_FLUSHING;

            // send ENQ
            NSTACK_LOG_SEND_FLUSH_SIG(g_nstack_log_client_fd
                                      [LOG_TYPE_NSTACK], ret);
            if (ret < 0)
            {
                g_nstack_log_server_state[LOG_TYPE_NSTACK] =
                    NSTACK_LOG_SER_STATE_RUNNING;
                g_nstack_log_server_state[LOG_TYPE_OPERATION] =
                    NSTACK_LOG_SER_STATE_RUNNING;
                return -1;
            }
            NSTACK_LOG_SEND_FLUSH_SIG(g_nstack_log_client_fd
                                      [LOG_TYPE_OPERATION], ret);
            if (ret < 0)
            {
                g_nstack_log_server_state[LOG_TYPE_OPERATION] =
                    NSTACK_LOG_SER_STATE_RUNNING;
                return -1;
            }
            break;
        case LOG_PRO_MASTER:
            g_nstack_log_server_state[LOG_TYPE_MASTER] =
                NSTACK_LOG_SER_STATE_FLUSHING;
            // send ENQ
            NSTACK_LOG_SEND_FLUSH_SIG(g_nstack_log_client_fd
                                      [LOG_TYPE_MASTER], ret);
            if (ret < 0)
            {
                g_nstack_log_server_state[LOG_TYPE_MASTER] =
                    NSTACK_LOG_SER_STATE_RUNNING;
                return -1;
            }
            break;
        case LOG_PRO_OMC_CTRL:
            g_nstack_log_server_state[LOG_TYPE_CTRL] =
                NSTACK_LOG_SER_STATE_FLUSHING;
            // send ENQ
            NSTACK_LOG_SEND_FLUSH_SIG(g_nstack_log_client_fd[LOG_TYPE_CTRL],
                                      ret);
            if (ret < 0)
            {
                g_nstack_log_server_state[LOG_TYPE_CTRL] =
                    NSTACK_LOG_SER_STATE_RUNNING;
                return -1;
            }
            break;
        default:
            return 0;
    }

    if (nstack_log_current_time2msec(&start))
    {
        return -1;
    }

    while (1)
    {
        if (timeout > 0)
        {
            if (nstack_log_current_time2msec(&end))
            {
                break;
            }
            if (end < start || (end - start) > timeout)
            {
                break;
            }
        }

        flushed = 1;
        for (i = 0; i < MAX_LOG_TYPE; i++)
        {
            if (g_nstack_log_server_state[i] != NSTACK_LOG_SER_STATE_RUNNING)
            {
                flushed = 0;
                break;
            }
        }
        if (flushed)
        {
            return 0;
        }
        sys_sleep_ns(0, 500000);
    }

    return -1;
}

/*****************************************************************************
*   Prototype    : nstack_log_client_init
*   Description  : init the nstack log domain socket, which use to handle
*                  the log with a thread of the domain connect, store the
*                  client fd, for client side.
*   Input        : int proc_type
*                  ...
*   Output       : None
*   Return Value : 0 means success, -1 means fail.
*   Calls        :
*   Called By    :
*****************************************************************************/
int nstack_log_client_init(int proc_type)
{
    int connfd = -1;
    int connfd_opt = -1;

    switch (proc_type)
    {
        case LOG_PRO_NSTACK:
            //get the con fd and store the fd to g_nstack_log_client_fd
            connfd = nstack_log_sock_conn(nstack_sock_running);
            g_nstack_log_client_fd[LOG_TYPE_NSTACK] = connfd;
            connfd_opt = nstack_log_sock_conn(nstack_sock_operation);
            if (connfd_opt < 0)
            {
                save_pre_init_log(NSLOG_ERR,
                                  "asyn client init fail]connfd_opt=%d",
                                  connfd_opt);
                return -1;
            }
            g_nstack_log_client_fd[LOG_TYPE_OPERATION] = connfd_opt;
            break;
        case LOG_PRO_MASTER:
            connfd = nstack_log_sock_conn(nstack_sock_master);
            g_nstack_log_client_fd[LOG_TYPE_MASTER] = connfd;
            break;
        case LOG_PRO_OMC_CTRL:
            connfd = nstack_log_sock_conn(nstack_sock_ctrl);
            g_nstack_log_client_fd[LOG_TYPE_CTRL] = connfd;
            break;
        default:
            save_pre_init_log(NSLOG_ERR, "process invalid]proc_type=%d",
                              proc_type);
            return -1;
    }

    if (connfd < 0)
    {
        save_pre_init_log(NSLOG_ERR, "asyn client init fail]connfd=%d",
                          connfd);
        return -1;
    }

    if (proc_type == LOG_PRO_NSTACK)
    {
        save_pre_init_log(NSLOG_INF,
                          "asyn client init success]connfd=%d,connfd_opt=%d",
                          connfd, connfd_opt);
    }
    else
    {
        save_pre_init_log(NSLOG_INF, "asyn client init success]connfd=%d",
                          connfd);
    }

    return 0;
}

/*****************************************************************************
*   Prototype    : nstack_log_client_send
*   Description  : send the log data to the file, file_type will get the fd
*                  for the specified conn.
*   Input        : int file_type
*                : char *buffer
*                : size_t buflen
*                  ...
*   Output       : None
*   Return Value : 0 means success, -1 means fail.
*   Calls        :
*   Called By    :
*****************************************************************************/
int nstack_log_client_send(int file_type, char *buffer, size_t buflen)
{
    int connfd = -1;
    int num = -1;
    int count = 2;              //if errno is EAGAIN or EINTR, try twice
    if ((NULL == buffer) || (buflen == 0) || (file_type < 0)
        || (file_type > LOG_TYPE_CTRL))
    {
        return -1;
    }

    //get the fd as the file_type specified.
    connfd = g_nstack_log_client_fd[file_type];
    if (connfd < 0)
    {
        NS_PTHREADLOG(file_type, NSLOG_ERR,
                      "connfd invalid]connfd=%d,file_type=%d", connfd,
                      file_type);
        goto async_err;
    }

    while (count-- > 0)
    {
        // write to client fd
        if ((num =
             nsfw_base_send(connfd, buffer, buflen, MSG_NOSIGNAL)) == buflen)
        {
            break;
        }
        else if (num <= 0)
        {
            if (num == 0 || ((errno != EAGAIN) && (errno != EINTR)))
            {
                NS_PTHREADLOG(file_type, NSLOG_ERR,
                              "async log module fail, domain socket close]g_nstack_log_client_fd[%d]=%d,num=%d,errno=%d",
                              file_type, connfd, num, errno);
                (void) nsfw_base_close(connfd);
                g_nstack_log_client_fd[file_type] = -1;
                goto async_err;
            }
        }
        else
        {
            break;
        }
    }

    return 0;

  async_err:
    NS_PTHREADLOG(file_type, NSLOG_ERR,
                  "current process will turn DIO synchron log module]buflen=%zu,buffer=%s",
                  buflen, buffer);
    log_asyn_inited = FALSE;

    return -1;
}

/*****************************************************************************
*   Prototype    : nstack_log_level_valid
*   Description  : check if the level is valid.
*   Input        : uint32_t level
*                  ...
*   Output       : None
*   Return Value : TRUE means success, FALSE means fail
*   Calls        :
*   Called By    :
*****************************************************************************/
bool nstack_log_level_valid(uint32_t level)
{
    switch (level)
    {
        case NSLOG_CUS:
        case NSLOG_DBG:
        case NSLOG_INF:
        case NSLOG_WAR:
        case NSLOG_ERR:
        case NSLOG_EMG:
            break;
        default:
            return FALSE;
    }
    return TRUE;
}

/*****************************************************************************
*   Prototype    : save_pre_init_log
*   Description  : save the pre init log for nstack as the log module still
*                  be unavailable.
*   Input        : uint32_t level
*                : char *fmt
*                  ...
*   Output       : None
*   Return Value : void
*   Calls        :
*   Called By    :
*****************************************************************************/

/* change the print level, not only has err */
void save_pre_init_log(uint32_t level, char *fmt, ...)
{
    va_list ap;
    int ret = 0;
    /*add pre_init_log_count rang check */
    if (!nstack_log_level_valid(level)
        || pre_init_log_count >= MAX_PRE_INIT_LOG_COUNT
        || pre_init_log_count < 0)
    {
        return;
    }

    pre_init_log[pre_init_log_count].log_buffer[PRE_INIT_LOG_LENGTH - 1] =
        '\0';

    (void) va_start(ap, fmt);   /*keep behavior same with C00,and it won't any effect here */
    ret =
        vsnprintf_s(pre_init_log[pre_init_log_count].log_buffer,
                    PRE_INIT_LOG_LENGTH, PRE_INIT_LOG_LENGTH - 1, fmt, ap);
    if (-1 == ret)
    {
        va_end(ap);
        return;
    }
    va_end(ap);
    pre_init_log[pre_init_log_count].level = level;
    pre_init_log_count++;
    return;
}

/*****************************************************************************
*   Prototype    : get_pre_init_log_count
*   Description  : get the count value of the pre log record.
*   Input        : None
*                  ...
*   Output       : log count num
*   Return Value : nonnegative number
*   Calls        :
*   Called By    :
*****************************************************************************/
int get_pre_init_log_count()
{
    int count = pre_init_log_count;
    if ((count < 0) || (count >= MAX_PRE_INIT_LOG_COUNT))
    {
        return 0;
    }
    return count;
}

/*****************************************************************************
*   Prototype    : get_pre_init_log_buffer
*   Description  : get the stored log content of the pre log, the content will
*                  copy to the input parameter array for print.
*   Input        : struct pre_init_info pre_buf[]
*                : uint32_t size
*                  ...
*   Output       : None
*   Return Value : 0 means success, -1 means fail.
*   Calls        :
*   Called By    :
*****************************************************************************/
int get_pre_init_log_buffer(struct pre_init_info *pre_buf, uint32_t size)
{
    int ret = -1;
    size_t array_size = sizeof(struct pre_init_info) * size;
    if (NULL == pre_buf || size > MAX_PRE_INIT_LOG_COUNT
        || (sizeof(pre_init_log) != array_size))
    {
        return -1;
    }

    ret = memcpy_s(pre_buf, array_size, pre_init_log, array_size);
    if (EOK != ret)
    {
        return -1;
    }
    return 0;
}

/*****************************************************************************
*   Prototype    : get_level_desc
*   Description  : get the first letter as the level.
*   Input        : uint32_t level
*                  ...
*   Output       : first letter of the level
*   Return Value : char *
*   Calls        :
*   Called By    :
*****************************************************************************/
char *get_level_desc(uint32_t level)
{
    switch (level)
    {
        case NSLOG_DBG:
            return "D";
        case NSLOG_INF:
            return "I";
        case NSLOG_WAR:
            return "W";
        case NSLOG_ERR:
            return "E";
        case NSLOG_EMG:
            /* PDT use fatal, so here use F */
            return "F";
        default:
            return "E";
    }
}

/*****************************************************************************
*   Prototype    : nstack_log_get_prefix
*   Description  : assemble the log prefix content, the content contain the level
*                  first letter, and timestamp
*   Input        : uint32_t level
*                : char *buffer
*                : uint32_t length
*                  ...
*   Output       : buffer store the pre_log
*   Return Value : >=0 means success, -1 means fail.
*   Calls        :
*   Called By    :
*****************************************************************************/
int nstack_log_get_prefix(uint32_t level, char *buffer, uint32_t length)
{
    if ((NULL == buffer) || length == 0)
    {
        return -1;
    }

    int ret = -1;
    char *level_str = "E";
    struct timeval t_val;
    struct tm now_time;

    /* limit log file size and log file count- Begin */
    /*gettimeofday is not change to clock_gettime as this is for log and gettimeofday only
       makes sense here */
    (void) gettimeofday(&t_val, NULL);
    time_t t_sec = (time_t) t_val.tv_sec;
    (void) gmtime_r(&t_sec, &now_time);

    level_str = get_level_desc(level);

    /* There are some unsafe function ,need to be replace with safe function */
    /* modify %02d:%02d:%02d:%06ld:%s to "%02d:%02d:%02d.%06ld %s" */
    ret = sprintf_s(buffer, length, "%s%02d%02d %02d:%02d:%02d.%06ld",
                    level_str, now_time.tm_mon + 1, now_time.tm_mday,
                    now_time.tm_hour, now_time.tm_min, now_time.tm_sec,
                    (long) t_val.tv_usec);
    if (-1 == ret)
    {
        return -1;
    }

    return ret;

}

/*****************************************************************************
*   Prototype    : nstack_log_print_buffer
*   Description  : get the log prefix content, and assemble the log with format,
*                  then use glog print direct, as in a single thread, no block.
*   Input        : uint32_t file_type
*                : uint32_t level
*                : const char *format
*                  ...
*   Output       : NA
*   Return Value : void
*   Calls        :
*   Called By    : nstack_log_server_process
*****************************************************************************/
void nstack_log_print_buffer(uint32_t log_type, uint32_t level,
                             const char *format, ...)
{
    if (NULL == format)
    {
        return;
    }

    va_list ap;
    int ret;
    char pre_buffer[PRE_INIT_LOG_LENGTH] = { 0 };
    char buffer[MAX_BUFFER_LEN] = { 0 };
    char format_buffer[MAX_BUFFER_LEN] = { 0 };

    ret = nstack_log_get_prefix(level, pre_buffer, sizeof(pre_buffer));
    if (ret < 0)
    {
        return;
    }

    ret =
        sprintf_s(format_buffer, sizeof(format_buffer), "%s %s", pre_buffer,
                  format);
    if (ret < 0)
    {
        return;
    }

    va_start(ap, format);       /*no need to check return */
    ret = vsprintf_s(buffer, sizeof(buffer), format_buffer, ap);
    if (-1 == ret)
    {
        va_end(ap);
        return;
    }
    va_end(ap);

    buffer[sizeof(buffer) - 1] = '\0';

    // print the buf
    glog_print_buffer(log_type, buffer, ret);

    return;
}
