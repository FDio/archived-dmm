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

#include "lb.h"
#include "cps.h"

inline static void
cps_s_close (struct cps_thread *thread)
{
  int fd;
  struct epoll_event ev = { 0 };

  for (fd = thread->server; fd >= 0; fd = CPS_CONN (fd)->next)
    {
      (void) _epoll_ctl (thread->epfd, EPOLL_CTL_DEL, fd, &ev);
      _close (fd);
    }

  thread->server = -1;
}

int
cps_s_listen (struct cps_thread *thread)
{
  int i;

  for (i = 0; i < thread->server_num; ++i)
    {
      int fd, ret;
      struct timespec dummy;
      struct epoll_event event;
      struct sockaddr_in *server = &thread->s_addr[i];

      fd = _socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
      ERR_RETURN (fd < 0, -1, "socket()=%d:%d\n", fd, errno);

      ret = _bind (fd, (struct sockaddr *) server, sizeof (*server));
      ERR_RETURN (ret, -1, "bind(%d)=%d:%d\n", fd, ret, errno);

      ret = set_nonblock (fd);
      ERR_RETURN (ret, -1, "set_nonblock(%d)=%d:%d\n", fd, ret, errno);

      ret = _listen (fd, SOMAXCONN);
      ERR_RETURN (ret, -1, "listen(%d)=%d:%d\n", fd, ret, errno);

      event.events = EPOLLIN | EPOLLET;
      event.data.u64 = CPS_EV_DATA (i, fd);
      ret = _epoll_ctl (thread->epfd, EPOLL_CTL_ADD, fd, &event);
      ERR_RETURN (ret, -1, "epoll_ctl(%d, %d)=%d:%d\n", thread->epfd, fd, ret,
                  errno);

      out ("[%d.%d:%d] listen on %s\n", thread->index, i, fd,
           f_inaddr (server));

      cps_add_server (thread, fd, i);
    }

  return 0;
}

int
cps_s_accept (struct cps_thread *thread, int server_fd)
{
  while (cps.run_state == CPS_RUNNING)
    {
      int fd, ret;
      struct timespec begin;
      struct epoll_event event;
#if defined(DEBUG)
      struct sockaddr_in addr;
      socklen_t len = sizeof (addr);
#endif

      LB_TIME (begin);

#if defined(DEBUG) && 0
      fd =
        _accept4 (server_fd, (struct sockaddr *) &addr, &len, SOCK_NONBLOCK);
#else
      fd = _accept4 (server_fd, NULL, NULL, SOCK_NONBLOCK);
#endif
      if (fd < 0)
        {
          int e = errno;
          if (e == EAGAIN || e == EWOULDBLOCK)
            return 0;
          DBG ("->accept4(%d)=%d:%d\n", server_fd, fd, e);
          CPS_CNT_INC_E (thread, CPS_CNT_ACCEPT_ERR, errno);
          return -1;
        }

      CPS_REC_INC (thread, CPS_REC_INIT);
//                DBG("(%d, %d) -> accepted(%d) %d: %s", thread->index, sid, server->fd, fd, f_inaddr(&addr));

      if (fd >= CPS_MAX_FD)
        {
          _close (fd);
          CPS_REC_INC (thread, CPS_REC_FAIL);
          continue;
        }

      ret = set_nodelay (fd, 1);
      if (ret)
        CPS_CNT_INC_E (thread, CPS_CNT_NODELAY_ERR, errno);

      event.events = EPOLLIN | EPOLLET;
      event.data.u64 = CPS_EV_DATA (CPS_CONN_SID, fd);
      ret = _epoll_ctl (thread->epfd, EPOLL_CTL_ADD, fd, &event);
      if (ret)
        {
          _close (fd);
          CPS_CNT_INC_E (thread, CPS_CNT_EPOLL_ERR, errno);
          CPS_REC_INC (thread, CPS_REC_FAIL);
          DBG ("epoll_ctl(%d, %d)=%d:%d\n", thread->epfd, fd, ret, errno);
          continue;
        }

      cps_add_conn (thread, fd, -cps.req_len, &begin);
    }

  return 0;
}

int
cps_s_io (struct cps_thread *thread, int fd, uint32_t events)
{
  static char buf[CPS_DATA_MAX];

  int ret;
  struct cps_conn *conn = CPS_CONN (fd);

  DBG ("(%d, %d, %x) conn:{size:%d next:%d prev:%p:%d}\n",
       thread->index, fd, events, conn->size, conn->next, conn->prev,
       *conn->prev);

  if (events & EPOLLERR)
    {
      CPS_CNT_INC (thread, CPS_CNT_ERR_EVENT);
      DBG ("(%d, %d, 0x%x)\n", thread->index, fd, events);
      goto ERR;
    }

  if (0 == (events & EPOLLIN))
    return 0;

  while (1)
    {
      if (cps.run_state <= CPS_INIT)
        goto ERR;

      ret = _recv (fd, buf, sizeof (buf), 0);
      if (ret > 0)
        {
          conn->size += ret;
          if (conn->size >= 0)
            {
              CPS_REC_TIMED_INC (thread, CPS_REC_RECV, conn->last);
              break;            /* receive success */
            }
        }
      else
        {
          if (ret < 0)
            {
              const int e = errno;
              if (e == EWOULDBLOCK || e == EAGAIN)
                return 0;
              if (e == EINTR)
                continue;
              CPS_CNT_INC_E (thread, CPS_CNT_RECV_ERR, e);
            }
          else
            {
              CPS_CNT_INC (thread, CPS_CNT_RECV_ERR);
            }
          DBG ("->recv(%d,, %ld)=%d:%d\n", fd, sizeof (buf), ret, errno);
          goto ERR;
        }
    }

  conn->size = 0;

  while (cps.run_state > CPS_INIT)
    {
      ret = _send (fd, buf, cps.res_len - conn->size, 0);
      if (ret > 0)
        {
          conn->size += ret;
          if (conn->size >= cps.res_len)
            {
              _close (fd);
              CPS_REC_TIMED_INC (thread, CPS_REC_SEND, conn->last);
              cps_rem_conn (thread, fd, conn);
              return 0;
            }
        }
      else
        {
          if (ret < 0)
            {
              const int e = errno;
              if (e == EWOULDBLOCK || e == EAGAIN || e == EINTR)
                continue;
              CPS_CNT_INC_E (thread, CPS_CNT_SEND_ERR, e);
            }
          else
            {
              CPS_CNT_INC (thread, CPS_CNT_SEND_ERR);
            }
          DBG ("->send(%d,, %d)=%d:%d\n", fd, cps.res_len - conn->size, ret,
               errno);
          goto ERR;
        }
    }

  return 0;

ERR:
  _close (fd);
  cps_rem_conn (thread, fd, conn);
  CPS_REC_INC (thread, CPS_REC_FAIL);
  return -1;
}

void *
cps_s_thread (void *arg)
{
  int num = 0;
  struct cps_thread *thread = (struct cps_thread *) arg;
  struct epoll_event *event = thread->event;

  out ("[%d] initialize thread %ld server:%d core:%d epfd:%d\n",
       thread->index, pthread_self (), thread->server_num, thread->core,
       thread->epfd);

  if (cps_s_listen (thread))
    {
      cps.run_state = CPS_ERROR;
      return NULL;
    }

  futex_wait (&cps.run_state, CPS_INIT);

  while (1)
    {

      if (num > 0)
        {
          int sid = CPS_EV_SID (event->data.u64);
          int fd = CPS_EV_FD (event->data.u64);
          DBG ("epoll evnet{sid:%d fd:%d event:%x}\n", sid, fd,
               event->events);
          if (sid >= 0)
            {
              if (event->events & EPOLLIN)
                {
                  (void) cps_s_accept (thread, fd);
                }
              if (event->events & EPOLLERR)
                {
                  wrn ("Error event for server %d\n", fd);
                }
            }
          else
            {
              if (fd >= CPS_MAX_FD)
                {
                  err ("Error connection index %d\n", fd);
                }
              else
                {
                  (void) cps_s_io (thread, fd, event->events);
                }
            }

          num--;
          event++;
        }

      if (num <= 0)
        {
          if (cps.run_state == CPS_CLOSING)
            {
              if (thread->server >= 0)
                cps_s_close (thread);
              if (thread->conn_num <= 0)
                break;
            }
          else if (cps.run_state <= CPS_INIT)
            {
              break;
            }

          event = thread->event;
          num = _epoll_wait (thread->epfd, event, cps.evnum, CPS_EPWAIT_MS);
          if (num < 0)
            {
              int e = errno;
              if (e != EINTR && e != ETIMEDOUT)
                CPS_CNT_INC_E (thread, CPS_CNT_EPOLL_ERR, e);
            }
        }
    }

  __sync_fetch_and_sub (&cps.active_thread, 1);
  return NULL;
}
