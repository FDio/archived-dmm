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

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include "nstack_dmm_api.h"
#include "ff_config.h"
#include "ff_api.h"
#include "ff_epoll.h"

#define DMM_FSTACK_MAX_EP_EVENT 1024
#define DMM_FSTACK_ENV_DEBUG     "DMM_FSTACK_DEBUG"
#define DMM_FSTACK_ADPT_DEBUG dmm_fstack_debug
#define DMM_FSTACK_ENV_PROC_TYPE "DMM_FSTACK_PROC_TYPE"
#define DMM_FSTACK_ENV_PROC_ID "DMM_FSTACK_PROC_ID"
#define DMM_FSTACK_ENV_CONF_FILE "DMM_FSTACK_CONF_FILE"

static unsigned int dmm_fstack_debug;

typedef struct dmm_fstack
{
  int epfd;
  long unsigned int epoll_threadid;
  nstack_event_cb regVal;
  int (*p_epoll_create) (int size);
  unsigned int (*p_epoll_ctl) (int epFD, int ctl_ops, int proFD,
                               struct epoll_event * events);
  unsigned int (*p_epoll_wait) (int epfd, struct epoll_event * events,
                                int maxevents, int timeout);
  int (*p_close) (int fd);
} dmm_fstack_t;

dmm_fstack_t g_dmm_fstack;

unsigned int
fstack_ep_ctl_ops (int epFD, int proFD, int ctl_ops,
                   struct epoll_event *events, void *pdata)
{
  struct epoll_event tmpEvt;
  int ret = 0;
  int dmm_epfd;

  tmpEvt.data.ptr = pdata;
  tmpEvt.events = events->events;
  tmpEvt.events |= (EPOLLIN | EPOLLOUT);

  if (DMM_FSTACK_ADPT_DEBUG > 0)
    fprintf (stdout, "DMM VCL ADPT<%d>: epfd=%d,fd=%d,ops=%d, events=%u",
             getpid (), epFD, proFD, ctl_ops, events->events);

  dmm_epfd = g_dmm_fstack.epfd;
  switch (ctl_ops)
    {
    case nstack_ep_triggle_add:
      ret =
        g_dmm_fstack.p_epoll_ctl (dmm_epfd, EPOLL_CTL_ADD, proFD, &tmpEvt);
      break;
    case nstack_ep_triggle_mod:
      ret =
        g_dmm_fstack.p_epoll_ctl (dmm_epfd, EPOLL_CTL_MOD, proFD, &tmpEvt);
      break;
    case nstack_ep_triggle_del:
      ret =
        g_dmm_fstack.p_epoll_ctl (dmm_epfd, EPOLL_CTL_DEL, proFD, &tmpEvt);
      break;
    default:
      ret = -1;
      break;
    }
  return ret;
}

int
fr_init (void)
{
  int ret;
  char config_file[1024] = "--conf=config.ini";
  char proc_type[1024] = "--proc-type=primary";
  char proc_id[1024] = "--proc-id=0";

  /* if env isn't set consider DPDK process type as primary */
  if (getenv (DMM_FSTACK_ENV_CONF_FILE))
    {
      sprintf (proc_type, "--conf=%s", getenv (DMM_FSTACK_ENV_CONF_FILE));
    }
  if (getenv (DMM_FSTACK_ENV_PROC_TYPE))
    {
      sprintf (proc_type, "--proc-type=%s",
               getenv (DMM_FSTACK_ENV_PROC_TYPE));
    }
  if (getenv (DMM_FSTACK_ENV_PROC_ID))
    {
      sprintf (proc_id, "--proc-id=%d",
               atoi (getenv (DMM_FSTACK_ENV_PROC_ID)));
    }

  char *argv[] = {
    "dmm-fstack",
    config_file,
    proc_type,
    proc_id,
    NULL
  };

  const int argc = sizeof (argv) / sizeof (argv[0]) - 1;

  ret = ff_init (argc, argv);
  if (ret)
    return -1;

  return 0;
}

static pid_t
ff_fork (void)
{
  return -1;
}

int
fr_run (void *loop)
{
  ff_run (loop, NULL);
  return 0;
}

static int
ff_accept4 (int sockfd, struct sockaddr *addr, socklen_t * addrlen, int flags)
{
  int fd;

  fd = ff_accept (sockfd, (struct linux_sockaddr *) addr, addrlen);
  if (fd < 0)
    return fd;

  if (flags & SOCK_NONBLOCK)
    {
      (void) ff_ioctl (sockfd, FIONBIO, 1);
    }

  if (flags & SOCK_CLOEXEC)
    {
    }

  return fd;
}

void
dmm_fstack_epoll ()
{
  int num, i;

  struct epoll_event events[DMM_FSTACK_MAX_EP_EVENT];

  num =
    g_dmm_fstack.p_epoll_wait (g_dmm_fstack.epfd, events,
                               DMM_FSTACK_MAX_EP_EVENT, 0);
  for (i = 0; i < num; ++i)
    {
      g_dmm_fstack.regVal.event_cb (events[i].data.ptr, events[i].events);
    }

  return;
}

int
dmm_fstack_init ()
{
  char *env_var_str;
  int rv = 0;

  if (0 != fr_init ())
    {
      return -1;
    }

  env_var_str = getenv (DMM_FSTACK_ENV_DEBUG);
  if (env_var_str)
    {
      unsigned int tmp;
      if (sscanf (env_var_str, "%u", &tmp) != 1)
        fprintf (stdout,
                 "DMM_FSTACK_ADPT: WARNING: Invalid debug level specified "
                 "in the environment variable " DMM_FSTACK_ENV_DEBUG
                 " (%s)!\n", env_var_str);
      else
        {
          dmm_fstack_debug = tmp;
          if (DMM_FSTACK_ADPT_DEBUG > 0)
            fprintf (stdout,
                     "DMM_FSTACK_ADPT: configured DMM FSTACK ADPT debug (%u) from "
                     "DMM_STACK_ENV_DEBUG ", dmm_fstack_debug);
        }
    }

  g_dmm_fstack.epfd = g_dmm_fstack.p_epoll_create (50);
  if (g_dmm_fstack.epfd < 0)
    return g_dmm_fstack.epfd;

  return 0;
}

int
fstack_stack_register (nstack_proc_cb * proc_fun, nstack_event_cb * event_ops)
{
#define NSTACK_MK_DECL(ret, fn, args) proc_fun->socket_ops.pf##fn = (void*)ff_##fn;
#include "declare_syscalls.h"
#undef NSTACK_MK_DECL
  g_dmm_fstack.p_epoll_ctl = dlsym (event_ops->handle, "ff_epoll_ctl");
  g_dmm_fstack.p_epoll_create = dlsym (event_ops->handle, "ff_epoll_create");
  g_dmm_fstack.p_epoll_wait = dlsym (event_ops->handle, "ff_epoll_wait");
  g_dmm_fstack.p_close = dlsym (event_ops->handle, "ff_close");
  g_dmm_fstack.regVal = *event_ops;

  proc_fun->socket_ops.pfselect = NULL;

  proc_fun->extern_ops.module_init = dmm_fstack_init;
  proc_fun->extern_ops.ep_ctl = fstack_ep_ctl_ops;
  proc_fun->extern_ops.ep_getevt = NULL;
  proc_fun->extern_ops.run = fr_run;
  proc_fun->extern_ops.ep_prewait = dmm_fstack_epoll;
  return 0;
}
