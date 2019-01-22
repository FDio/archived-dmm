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

struct cps_frag
{
  struct timespec begin;
  uint64_t count;
};

struct cps_run
{
  struct cps_frag frag[CPS_FRAG_NUM];
  uint64_t total;
  uint32_t fid;
  int sid, ci, ii;
  struct sockaddr_in addr;
};

inline static void
cps_c_next (struct cps_thread *thread, struct cps_run *run)
{
  if (thread->loop == CPS_LOOP_CF)
    {
      if (++run->ii >= thread->c_addr[run->ci].ip_num)
        {
          run->ii = 0;
          if (++run->ci == thread->client_num)
            {
              run->ci = 0;
              if (++run->sid >= thread->server_num)
                run->sid = 0;
            }
        }
      run->addr.sin_addr.s_addr =
        htonl (thread->c_addr[run->ci].ip + run->ii);
    }
  else if (thread->loop == CPS_LOOP_SF)
    {
      if (++run->sid >= thread->server_num)
        {
          run->sid = 0;
          if (++run->ii >= thread->c_addr[run->ci].ip_num)
            {
              run->ii = 0;
              if (++run->ci >= thread->client_num)
                run->ci = 0;
            }
          run->addr.sin_addr.s_addr =
            htonl (thread->c_addr[run->ci].ip + run->ii);
        }
    }
  else
    {
      if (++run->sid == thread->server_num)
        run->sid = 0;
      if (++run->ii >= thread->c_addr[run->ci].ip_num)
        {
          run->ii = 0;
          if (++run->ci == thread->client_num)
            run->ci = 0;
        }
      run->addr.sin_addr.s_addr =
        htonl (thread->c_addr[run->ci].ip + run->ii);
    }
}

inline static int
cps_c_trigger (struct cps_thread *thread, struct cps_run *run)
{
  uint64_t nsec, num;
  struct timespec now;
  struct cps_frag *frag = &run->frag[run->fid % CPS_FRAG_NUM];
  struct cps_frag *from = &run->frag[(run->fid + 1) % CPS_FRAG_NUM];

  LB_TIME (now);

  if (LB_CMP_NS (now, frag->begin, CPS_FRAG_NS))
    {
      /* move to next fragment */
      frag = from;
      from = &run->frag[++run->fid % CPS_FRAG_NUM];
      run->total -= frag->count;
      frag->count = 0;
      frag->begin = now;
    }

  nsec = LB_SUB_NS (now, from->begin);
  num = thread->rate * nsec / NSOFS;
  if (num >= run->total)
    {
      run->total++;
      frag->count++;
      return 1;
    }

  return 0;
}

int
cps_c_create (struct cps_thread *thread, struct cps_run *run)
{
  int fd, ret;
  struct timespec begin;
  struct epoll_event event;

  CPS_REC_INC (thread, CPS_REC_INIT);
  LB_TIME (begin);

  fd = _socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0)
    {
      CPS_CNT_INC_E (thread, CPS_CNT_SOCKET_ERR, errno);
      CPS_REC_INC (thread, CPS_REC_FAIL);
      DBG ("->socket(...)=%d:%d\n", fd, errno);
      return -1;
    }

  if (fd >= CPS_MAX_FD)
    {
      CPS_CNT_INC (thread, CPS_CNT_GTFD);
      goto ERR;
    }

  ret = set_reuseaddr (fd, 1);
  if (ret)
    CPS_CNT_INC_E (thread, CPS_CNT_REUSEADDR_ERR, errno);

  ret = _bind (fd, (struct sockaddr *) &run->addr, sizeof (run->addr));
  if (ret)
    {
      CPS_CNT_INC_E (thread, CPS_CNT_BIND_ERR, errno);
      DBG ("->bind(%d, %s)=%d:%d\n", fd, f_inaddr (&run->addr), ret, errno);
      goto ERR;
    }
  ret = set_nodelay (fd, 1);
  if (ret)
    CPS_CNT_INC_E (thread, CPS_CNT_NODELAY_ERR, errno);

  ret = set_nonblock (fd);
  if (ret)
    {
      CPS_CNT_INC_E (thread, CPS_CNT_NONBLOCK_ERR, errno);
      goto ERR;
    }

  ret =
    _connect (fd, (struct sockaddr *) &thread->s_addr[run->sid],
              sizeof (thread->s_addr[run->sid]));
  if (ret)
    {
      const int e = errno;
      if (e != EINPROGRESS)
        {
          CPS_CNT_INC_E (thread, CPS_CNT_CONNECT_ERR, e);
          DBG ("->connect(%d, %s)=%d:%d\n", fd,
               f_inaddr (&thread->s_addr[run->sid]), ret, errno);
          goto ERR;
        }
    }

  event.events = EPOLLIN | EPOLLOUT | EPOLLET;
  event.data.u64 = CPS_EV_DATA (CPS_CONN_SID, fd);
  ret = _epoll_ctl (thread->epfd, EPOLL_CTL_ADD, fd, &event);
  if (ret)
    {
      CPS_CNT_INC_E (thread, CPS_CNT_EPOLL_ERR, errno);
      DBG ("->epoll_ctl(%d, ADD, %d)=%d:%d\n", thread->epfd, fd, ret, errno);
      goto ERR;
    }

  cps_add_conn (thread, fd, 0, &begin);

  return 0;

ERR:
  _close (fd);
  CPS_REC_INC (thread, CPS_REC_FAIL);
  return -1;
}

int
cps_c_io (struct cps_thread *thread, int fd, uint32_t events)
{
  int ret;
  static char buf[CPS_DATA_MAX];

//        struct cps_server *server = &thread->server[sid];
  struct cps_conn *conn = CPS_CONN (fd);

  if (events & EPOLLERR)
    {
      CPS_CNT_INC (thread, CPS_CNT_ERR_EVENT);
      DBG ("(%d, %d, %x) EPOLLERR\n", thread->index, fd, events);
      goto ERR;
    }

  if (conn->size >= 0)
    {
      if (0 == (events & EPOLLOUT))
        return 0;

      while (1)
        {
          if (cps.run_state <= CPS_INIT)
            return -1;

          ret = _send (fd, buf, cps.req_len - conn->size, 0);
          if (ret > 0)
            {
              conn->size += ret;
              if (conn->size >= cps.req_len)
                {
                  struct epoll_event event;
                  event.events = EPOLLIN;
                  event.data.u64 = CPS_EV_DATA (CPS_CONN_SID, fd);
                  conn->size = -cps.res_len;
                  ret = _epoll_ctl (thread->epfd, EPOLL_CTL_MOD, fd, &event);
                  if (ret)
                    {
                      CPS_CNT_INC_E (thread, CPS_CNT_EPOLL_ERR, errno);
                      DBG ("->epoll_ctl(%d, MOD, %d)=%d:%d\n", thread->epfd,
                           fd, ret, errno);
                      goto ERR;
                    }
                  CPS_REC_TIMED_INC (thread, CPS_REC_SEND, conn->last);
                  break;
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
                  CPS_CNT_INC_E (thread, CPS_CNT_SEND_ERR, e);
                }
              else
                {
                  CPS_CNT_INC (thread, CPS_CNT_SEND_ERR);
                }
              DBG ("->send(%d,, %d)=%d:%d\n", fd, cps.req_len - conn->size,
                   ret, errno);
              goto ERR;
            }
        }
    }

  if (0 == (events & EPOLLIN))
    return 0;

  while (cps.run_state > CPS_INIT)
    {
      ret = _recv (fd, buf, -conn->size, 0);
      if (ret > 0)
        {
          conn->size += ret;
          if (conn->size >= 0)
            {
              /* receive success */
              _close (fd);
              CPS_REC_TIMED_INC (thread, CPS_REC_RECV, conn->last);
              cps_rem_conn (thread, fd, conn);
              return 0;
            }
        }
      else
        {
          if (ret < 0)
            {
              const int e = errno;
              if (e == EWOULDBLOCK || e == EAGAIN)
                return 0;       /*wait event */
              if (e == EINTR)   /* The receive was interrupted by delivery of a signal... */
                continue;       /*recv again */
              CPS_CNT_INC_E (thread, CPS_CNT_RECV_ERR, e);
            }
          else
            {
              CPS_CNT_INC (thread, CPS_CNT_RECV_ERR);
            }
          DBG ("->recv(%d,, %d)=%d:%d\n", fd, -conn->size, ret, errno);
          goto ERR;             /* ret == 0 and not block meaning error */
        }
    }

  DBG ("(%d, %d) cannot run there\n", thread->index, fd);

ERR:
  _close (fd);
  CPS_REC_INC (thread, CPS_REC_FAIL);
  cps_rem_conn (thread, fd, conn);
  return -1;
}

void *
cps_c_thread (void *arg)
{
  int i, num = 0;
  struct cps_run run = { 0 };
  struct cps_thread *thread = (struct cps_thread *) arg;
  struct epoll_event *event = thread->event;

  run.addr.sin_family = AF_INET;
  run.addr.sin_port = htons (0);

  out
    ("[%d] initialize thread %ld client:%d server:%d rate:%lu core:%d epfd:%d\n",
     thread->index, pthread_self (), thread->client_num, thread->server_num,
     thread->rate, thread->core, thread->epfd);

  futex_wait (&cps.run_state, CPS_INIT);

  LB_TIME (run.frag[0].begin);
  for (i = 1; i < CPS_FRAG_NUM; ++i)
    run.frag[i].begin = run.frag[0].begin;

  while (1)
    {
      /* open 1 connect */
      if (cps.run_state == CPS_RUNNING)
        {
          if (cps_c_trigger (thread, &run))
            {
              cps_c_next (thread, &run);
              cps_c_create (thread, &run);
            }
        }
      else if (cps.run_state == CPS_CLOSING)
        {
          if (thread->conn_num <= 0)
            break;
        }
      else
        {
          break;
        }

      /* process 1 event */
      if (num > 0)
        {
          int fd = CPS_EV_FD (event->data.u64);
          DBG ("epoll event:{sid:%d fd:%d e:%x}\n",
               CPS_EV_SID (event->data.u64), fd, event->events);

          if ((uint32_t) fd >= CPS_MAX_FD)
            {
              CPS_CNT_INC (thread, CPS_CNT_FD_ERR);
            }
          else
            {
              (void) cps_c_io (thread, fd, event->events);
            }

          num--;
          event++;
        }

      /* wait events */
      if (num <= 0)
        {
          event = thread->event;
          num = _epoll_wait (thread->epfd, event, cps.evnum, 0);        /* no wait */
          if (num < 0)
            {
              int e = errno;
              if (e != EINTR)
                CPS_CNT_INC_E (thread, CPS_CNT_EPOLL_ERR, e);
            }
        }

    }

  __sync_fetch_and_sub (&cps.active_thread, 1);
  return NULL;
}
