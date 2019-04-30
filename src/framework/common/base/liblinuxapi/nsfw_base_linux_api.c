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

#include "nsfw_base_linux_api.h"
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>

#define NSFW_BASE_OK   0
#define NSFW_BASE_FAIL (-1)

#define nsfw_call_ret(symbol, para){ \
   if (NSFW_BASE_OK != nsfw_posix_api_init()) \
   { \
        return NSFW_BASE_FAIL; \
   } \
   if (g_nsfw_posix_api.pf##symbol)   \
   {   \
       return g_nsfw_posix_api.pf##symbol para;\
   }   \
   errno = ENOSYS; \
   return NSFW_BASE_FAIL; \
}

typedef enum
{
    BASE_STATE_INIT,
    BASE_STATE_SUCCESS,
    BASE_STATE_FAIL
} nsfw_base_state;

typedef struct __base_linux_api
{
#define BASE_MK_DECL(ret, fn, args)   ret (*pf##fn) args;
#include "base_linux_api_declare.h"
} base_linux_api;

nsfw_base_state g_nsfw_mudule_state = BASE_STATE_INIT;
pthread_mutex_t g_nsfw_init_mutex = PTHREAD_MUTEX_INITIALIZER;
base_linux_api g_nsfw_posix_api = { 0 };

void *g_linux_lib_handle = (void *) 0;

int nsfw_posix_symbol_load()
{
    g_linux_lib_handle = dlopen("libc.so.6", RTLD_NOW | RTLD_GLOBAL);
    if ((void *) 0 == g_linux_lib_handle)
    {
        return NSFW_BASE_FAIL;
    }
#define BASE_MK_DECL(ret, fn, args)  \
         g_nsfw_posix_api.pf##fn = (typeof(g_nsfw_posix_api.pf##fn))dlsym(g_linux_lib_handle, #fn);
#include <base_linux_api_declare.h>

    return NSFW_BASE_OK;
}

/*****************************************************************
Parameters    : void
Return        :
Description   :  linux posix api init with threadonce
*****************************************************************/
static inline int nsfw_posix_api_init()
{
    int iret = NSFW_BASE_OK;

    /*if init already, just return success, if init fail before, just return err */
    if (BASE_STATE_INIT != g_nsfw_mudule_state)
    {
        return (BASE_STATE_SUCCESS ==
                g_nsfw_mudule_state ? NSFW_BASE_OK : NSFW_BASE_FAIL);
    }

    (void) pthread_mutex_lock(&g_nsfw_init_mutex);

    /*if init already, just return success, if init fail before, just return err */
    if (BASE_STATE_INIT != g_nsfw_mudule_state)
    {
        (void) pthread_mutex_unlock(&g_nsfw_init_mutex);
        return (BASE_STATE_SUCCESS ==
                g_nsfw_mudule_state ? NSFW_BASE_OK : NSFW_BASE_FAIL);
    }

    iret = nsfw_posix_symbol_load();
    if (NSFW_BASE_OK == iret)
    {
        g_nsfw_mudule_state = BASE_STATE_SUCCESS;
    }
    else
    {
        g_nsfw_mudule_state = BASE_STATE_FAIL;
    }

    (void) pthread_mutex_unlock(&g_nsfw_init_mutex);
    return iret;
}
/* *INDENT-OFF* */
int nsfw_base_socket(int a, int b, int c)
{
   nsfw_call_ret(socket, (a, b, c))
}

int nsfw_base_bind(int a, const struct sockaddr* b, socklen_t c)
{
   nsfw_call_ret(bind, (a, b, c))
}

int nsfw_base_listen(int a, int b)
{
    nsfw_call_ret(listen, (a, b))
}

int nsfw_base_shutdown(int a, int b)
{
    nsfw_call_ret(shutdown, (a, b))
}

int nsfw_base_getaddrinfo(const char *a, const char *b, const struct addrinfo *c, struct addrinfo **d)
{
   nsfw_call_ret(getaddrinfo, (a, b, c, d))
}

int nsfw_base_getsockname(int a, struct sockaddr* b, socklen_t* c)
{
    nsfw_call_ret(getsockname, (a, b, c))
}

int nsfw_base_getpeername(int a, struct sockaddr* b, socklen_t* c)
{
    nsfw_call_ret(getpeername, (a, b, c))
}

int nsfw_base_getsockopt(int a, int b, int c, void* d, socklen_t* e)
{
    nsfw_call_ret(getsockopt, (a, b, c, d, e))
}

int nsfw_base_setsockopt(int a, int b, int c, const void* d, socklen_t e)
{
    nsfw_call_ret(setsockopt, (a, b, c, d, e))
}

int nsfw_base_accept(int a, struct sockaddr* b, socklen_t* c)
{
    nsfw_call_ret(accept, (a, b, c))
}

int nsfw_base_accept4(int a, struct sockaddr* b, socklen_t* c, int flags)
{
    nsfw_call_ret(accept4, (a, b, c, flags))
}

int nsfw_base_connect(int a, const struct sockaddr* b, socklen_t c)
{
    nsfw_call_ret(connect, (a, b, c))
}

ssize_t nsfw_base_recv(int a, void* b, size_t c, int d)
{
    nsfw_call_ret(recv, (a, b, c, d))
}

ssize_t nsfw_base_send(int a, const void* b, size_t c, int d)
{
    nsfw_call_ret(send, (a, b, c, d))
}

ssize_t nsfw_base_read(int a, void* b, size_t c)
{
    nsfw_call_ret(read, (a, b, c))
}

ssize_t nsfw_base_write(int a, const void* b, size_t c)
{
    nsfw_call_ret(write, (a, b, c))
}

ssize_t nsfw_base_writev(int a, const struct iovec * b, int c)
{
    nsfw_call_ret(writev, (a, b, c))
}

ssize_t nsfw_base_readv(int a, const struct iovec * b, int c)
{
    nsfw_call_ret(readv, (a, b, c))
}

ssize_t nsfw_base_sendto(int a, const void * b, size_t c, int d, const struct sockaddr *e, socklen_t f)
{
    nsfw_call_ret(sendto, (a, b, c, d, e, f))
}

ssize_t nsfw_base_recvfrom(int a, void *b, size_t c, int d,struct sockaddr *e, socklen_t *f)
{
    nsfw_call_ret(recvfrom, (a, b, c, d, e, f))
}

ssize_t nsfw_base_sendmsg(int a, const struct msghdr *b, int flags)
{
    nsfw_call_ret(sendmsg, (a, b, flags))
}

ssize_t nsfw_base_recvmsg(int a, struct msghdr *b, int flags)
{
    nsfw_call_ret(recvmsg, (a, b, flags))
}

int nsfw_base_close(int a)
{
    nsfw_call_ret(close, (a))
}

int nsfw_base_select(int a, fd_set *b, fd_set *c, fd_set *d, struct timeval *e)
{
    nsfw_call_ret(select, (a, b, c, d, e))
}

int nsfw_base_ioctl(int a, unsigned long b, unsigned long c)
{
    nsfw_call_ret(ioctl, (a, b, c))
}

int nsfw_base_fcntl(int a, int b, unsigned long c)
{
    nsfw_call_ret(fcntl, (a, b, c))
}

int nsfw_base_epoll_create(int a)
{
    nsfw_call_ret(epoll_create, (a))
}

int nsfw_base_epoll_create1(int a)
{
    nsfw_call_ret(epoll_create1, (a))
}

int nsfw_base_epoll_ctl(int a, int b, int c, struct epoll_event *d)
{
    nsfw_call_ret(epoll_ctl, (a, b, c, d))
}

int nsfw_base_epoll_wait(int a, struct epoll_event *b, int c, int d)
{
    nsfw_call_ret(epoll_wait, (a, b, c, d))
}

pid_t nsfw_base_fork(void)
{
    nsfw_call_ret(fork, ())
}
/* *INDENT-ON* */
