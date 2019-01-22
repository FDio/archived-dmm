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
#include "lp.h"

int
lp_send_reply (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  int ret;
  char *buf = worker->io_buf;

  while (sess->reply > 0)
    {
      const int LEN =
        sess->reply < LP_IOBUF_SIZE ? sess->reply : LP_IOBUF_SIZE;

      ret = _send (fd, buf, LEN, 0);
      if (ret > 0)
        {
          LP_ADD (worker, LP_REPLY_BYTE, ret);
          sess->reply -= ret;
        }
      else if (ret < 0)
        {
          int e = errno;
          if (e == EWOULDBLOCK || e == EAGAIN)
            return lp_set_epout (worker, fd, sess);
          if (e == EINTR)
            continue;
          LP_ERR (worker, LP_E_SEND, e);
          return -1;
        }
      else
        {
          LP_CNT (worker, LP_E_IOSEND0);
        }
    }

  LP_CNT (worker, LP_REPLY_COMP);

  if (sess->epout)
    {
      if (lp_epmod (worker, fd, EPOLLIN))
        {
          LP_ERR (worker, LP_E_EPMOD, errno);
          return -1;
        }
      sess->epout = 0;
    }

  return 0;
}

int
lp_just_query (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  char *buf = worker->io_buf;
  struct lp_io *io = (struct lp_io *) buf;
  int len = 0;

  while (1)
    {
      int ret;

      ret = _recv (fd, buf + len, LP_IOBUF_SIZE - len, 0);

      if (ret > 0)
        {
          LP_ADD (worker, LP_QUERY_BYTE, ret);
          len += ret;
          if (len >= sizeof (struct lp_io))
            break;
          LP_CNT (worker, LP_E_IOMORE);
        }
      else if (ret < 0)
        {
          int e = errno;
          if (e == EWOULDBLOCK || e == EAGAIN)
            {
              LP_CNT (worker, LP_E_IOMORE);
              continue;
            }
          if (e == EINTR)
            continue;
          LP_ERR (worker, LP_E_RECV, e);
          return -1;
        }
      else
        {
          //LP_CNT(worker, LP_E_IOSHUT);
          return -1;
        }
    }

  sess->query = htonl (io->query);
  sess->reply = htonl (io->reply);

  if (sess->query < LP_QUERY_MIN || sess->reply < 0)
    {
      LP_CNT (worker, LP_E_IOSIZE);
      return -1;
    }

  sess->query -= len;
  return 0;
}

int
lp_recv_query (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  int ret;
  char *buf = worker->io_buf;

  if (sess->query == 0)
    {
      ret = lp_just_query (worker, fd, sess);
      if (ret)
        return ret;
    }

  while (1)
    {
      ret = _recv (fd, buf, LP_IOBUF_SIZE, 0);
      if (ret > 0)
        {
          LP_ADD (worker, LP_QUERY_BYTE, ret);
          sess->query -= ret;
        }
      else if (ret < 0)
        {
          int e = errno;
          if (e == EWOULDBLOCK || e == EAGAIN)
            {
              if (sess->query > 0)
                return 1;
              break;
            }
          if (e == EINTR)
            continue;
          LP_ERR (worker, LP_E_RECV, e);
          return -1;
        }
      else
        {
          if (sess->query || sess->reply)
            {
              //LP_CNT(worker, LP_E_IOSHUT);
            }
          else
            LP_CNT (worker, LP_QUERY_COMP);
          return -1;
        }
    }

  LP_CNT (worker, LP_QUERY_COMP);

  if (sess->query < 0)
    {
      LP_CNT (worker, LP_E_IOEXCEED);
      sess->query = 0;
    }

  if (sess->reply)
    return lp_send_reply (worker, fd, sess);

  return 0;
}

inline static int
lp_service (struct lp_worker *worker, int fd, uint32_t events)
{
  struct lp_sess *sess = LP_SESS (fd);

  if (sess->state == LP_S_UNUSED)
    {
      LP_CNT (worker, LP_E_EPUNUSED);
      return 0;
    }

  if (events & EPOLLRDHUP)
    return -1;

  if (events & EPOLLERR)
    {
      LP_CNT (worker, LP_E_EPERR);
      DBG ("epoll event error, fd:%d event:0x%x\n", fd, events);
      return -1;
    }

  if ((events & (EPOLLIN | EPOLLOUT)) == (EPOLLIN | EPOLLOUT))
    {
      LP_CNT (worker, LP_E_EPINOUT);
      return -1;
    }

  if (events & EPOLLIN)
    return lp_recv_query (worker, fd, sess);

  if (events & EPOLLOUT)
    return lp_send_reply (worker, fd, sess);

  LP_CNT (worker, LP_E_EPEVENT);
  return -1;
}

void
lp_accept (struct lp_worker *worker, int listen_fd)
{
  while (lp.run_state == LP_EXEC)
    {
      int fd, ret;
      struct lp_sess *sess;

      LP_TIME_SET (begin);

      fd = _accept4 (listen_fd, NULL, NULL, SOCK_NONBLOCK);
      if (fd < 0)
        {
          int e = errno;
          if (e == EAGAIN || e == EWOULDBLOCK)
            return;
          if (e == EINTR)
            continue;
          LP_ERR (worker, LP_E_ACCEPT, e);
          DBG ("->accept4(%d)=%d:%d\n", listen_fd, fd, e);
          return;
        }
      else
        {
          LP_TIME_END (worker, LP_W_ACCEPT, begin);
        }

      if (fd >= LP_MAX_FD)
        {
          LP_CNT (worker, LP_FAILED);
          _close (fd);
          err ("accept fd(%d) >= LP_MAX_FD(%d)\n", fd, LP_MAX_FD);
          continue;
        }

      if (lp.nodelay)
        {
          ret = set_nodelay (fd, 1);
          if (ret)
            LP_ERR (worker, LP_E_NODELAY, errno);
        }

      ret = lp_epadd (worker, fd, EPOLLIN);
      if (ret)
        {
          int e = errno;
          LP_ERR2 (worker, LP_FAILED, LP_E_EPADD, e);
          _close (fd);
          DBG ("epoll_ctl(%d, %d)=%d:%d\n\n", worker->epfd, fd, ret, e);
          continue;
        }

      sess = lp_init_sess (worker, fd);
      LP_APPEND (worker->sess, fd, sess, sess);
      sess->state = LP_S_CONNECTED;
      LP_CNT (worker, LP_CONNECTED);

      LP_TIME_END (worker, LP_W_CREATE, begin);
    }
}

void
lp_server (struct lp_worker *worker)
{
  int num = 0;
  struct epoll_event *event;
  const int epfd = worker->epfd;

  while (lp.run_state == LP_EXEC)
    {
      if (num > 0)
        {
          const uint64_t type = LP_EV_TYPE (event->data.u64);
          const int fd = LP_EV_FD (event->data.u64);

          if (type == LP_LISTEN_TYPE)
            {
              lp_accept (worker, fd);
            }
          else if (type == LP_SESSION_TYPE)
            {
              if (lp_service (worker, fd, event->events) < 0)
                lp_del_sess (worker, fd);
            }
          else if (type == LP_CONTROL_TYPE)
            {
              break;
            }
          else
            {
              err ("epoll event error flag:%lx, fd:%d event:%x}\n",
                   LP_EV_FLAG (event->data.u64), fd, event->events);
            }
          num--;
          event++;
        }
      else
        {
          num = _epoll_wait (epfd, worker->ev_buf, LP_EVENT_NUM, -1);
          if (num > 0)
            {
              event = worker->ev_buf;
            }
          else if (num < 0)
            {
              int e = errno;
              if (e != EINTR && e != ETIMEDOUT)
                LP_ERR (worker, LP_E_EPWAIT, e);
            }
        }
    }
}

int
lp_listen (struct lp_worker *worker, int index)
{
  int fd, ret;
  struct epoll_event event;

  fd = _socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  ERR_RETURN (fd < 0, -1, "socket()=%d:%d\n", fd, errno);

  if (fd >= LP_MAX_FD)
    {
      err ("socket()=%d >= LP_MAX_FD(%d)\n", fd, LP_MAX_FD);
      (void) _close (fd);
      return -1;
    }

  LP_APPEND (worker->server, fd, lp_init_sess (worker, fd), sess);

  ret =
    _bind (fd, (struct sockaddr *) &worker->server_addr[index],
           sizeof (worker->server_addr[index]));
  ERR_RETURN (ret, -1, "bind(%d, %s)=%d:%d\n", fd,
              f_inaddr (&worker->server_addr[index]), ret, errno);

  ret = set_nonblock (fd);
  ERR_RETURN (ret, -1, "set_nonblock(%d)=%d:%d\n", fd, ret, errno);

  ret = _listen (fd, SOMAXCONN);
  ERR_RETURN (ret, -1, "listen(%d)=%d:%d\n", fd, ret, errno);

  event.events = EPOLLIN | EPOLLET;
  event.data.u64 = LP_EV_MK (LP_LISTEN_TYPE, fd);
  ret = _epoll_ctl (worker->epfd, EPOLL_CTL_ADD, fd, &event);
  ERR_RETURN (ret, -1, "epoll_ctl(%d, %d)=%d:%d\n", worker->epfd, fd, ret,
              errno);

  DBG ("worker %d server %d fd %d listen on %s\n", worker->index, index, fd,
       f_inaddr (&worker->server_addr[index]));
  return 0;
}
