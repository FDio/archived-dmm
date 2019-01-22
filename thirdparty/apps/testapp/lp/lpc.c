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

inline static int
lp_io_finish (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  int ret;

  sess->state = LP_S_IDLE;
  --sess->io_num;

  if (sess->io_num)
    {
      lp_add_rest (worker, fd, sess);
      sess->time.tv_sec += lp.test[sess->test].period;
      return 0;
    }

  if (lp.test[sess->test].close_after_io)
    return -1;

  if (lp_epdel (worker, fd))
    LP_ERR (worker, LP_E_EPDEL, errno);

  return 0;
}

int
lp_recv_reply (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  int ret;
  char *buf = worker->io_buf;

  LP_ASSERT (sess->query == 0);

  while (1)
    {
      ret = _recv (fd, buf, LP_IOBUF_SIZE, 0);
      if (ret > 0)
        {
          LP_ADD (worker, LP_REPLY_BYTE, ret);
          sess->reply -= ret;
        }
      else if (ret < 0)
        {
          int e = errno;
          if (e == EWOULDBLOCK || e == EAGAIN)
            {
              if (sess->reply > 0)
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
          if (sess->reply)
            LP_CNT (worker, LP_E_IOSHUT);
          else
            LP_CNT (worker, LP_REPLY_COMP);
          return -1;
        }
    }

  LP_CNT (worker, LP_REPLY_COMP);

  if (sess->reply < 0)
    {
      LP_CNT (worker, LP_E_IOEXCEED);
      sess->reply = 0;
    }

  return lp_io_finish (worker, fd, sess);
}

int
lp_more_query (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  int ret;
  char *buf = worker->io_buf;

  LP_ASSERT (sess->io_num);

  while (sess->query > 0)
    {
      const int LEN =
        sess->query < LP_IOBUF_SIZE ? sess->query : LP_IOBUF_SIZE;

      ret = _send (fd, buf, LEN, 0);
      if (ret > 0)
        {
          LP_ADD (worker, LP_QUERY_BYTE, ret);
          sess->query -= ret;
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

  LP_CNT (worker, LP_QUERY_COMP);

  if (sess->epout)
    {
      if (lp_epmod (worker, fd, EPOLLIN))
        {
          LP_ERR (worker, LP_E_EPMOD, errno);
          return -1;
        }
      sess->epout = 0;
    }

  if (!sess->reply)
    {
      return lp_io_finish (worker, fd, sess);
    }

  sess->state = LP_S_REPLY;
  return 0;
}

int
lp_new_query (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  int ret, len = 0;
  char *buf = worker->io_buf;
  struct lp_io *io = (struct lp_io *) buf;

  LP_ASSERT (sess->state == LP_S_IDLE);
  LP_ASSERT (sess->query == 0);
  LP_ASSERT (sess->reply == 0);
  LP_ASSERT (sess->io_num);

  sess->state = LP_S_QUERY;
  sess->query = lp.test[sess->test].query;
  sess->reply = lp.test[sess->test].reply;

  io->query = htonl (sess->query);
  io->reply = htonl (sess->reply);

  while (1)
    {
      ret = _send (fd, buf + len, sess->query - len, 0);
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
          LP_ERR (worker, LP_E_SEND, e);
          return -1;
        }
      else
        {
          LP_CNT (worker, LP_E_IOSEND0);
        }
    }

  sess->query -= len;

  return lp_more_query (worker, fd, sess);
}

int
lp_pre_connect (struct lp_worker *worker, int fd, struct sockaddr_in *c_addr)
{
  int ret;

  if (fd >= LP_MAX_FD)
    {
      LP_CNT (worker, LP_FAILED);
      err ("fd(%d) >= LP_MAX_FD(%d)\n", fd, LP_MAX_FD);
      return -1;
    }

  ret = set_reuseaddr (fd, 1);
  if (ret)
    {
      const int e = errno;
      LP_ERR (worker, LP_E_REUSEADDR, e);
      DBG ("set_reuseaddr(%d, 1)=%d:%d\n", fd, ret, e);
    }

  ret = set_reuseport (fd, 1);
  if (ret)
    {
      const int e = errno;
      LP_ERR (worker, LP_E_REUSEPORT, errno);
      DBG ("set_reuseport(%d, 1)=%d:%d\n", fd, ret, e);
    }

  if (c_addr->sin_addr.s_addr != INADDR_ANY || c_addr->sin_port != 0)
    {
      LP_TIME_SET (bind_begin);
      ret =
        _bind (fd, (struct sockaddr *) c_addr, sizeof (struct sockaddr_in));
      LP_TIME_END (worker, LP_W_BIND, bind_begin);
      if (ret)
        {
          int e = errno;
          if (e == EADDRINUSE)
            return -1;
          LP_ERR2 (worker, LP_FAILED, LP_E_BIND, errno);
          DBG ("->bind(%d, %s)=%d:%d\n", fd, f_inaddr (c_addr), ret, errno);
          return -1;
        }
    }

  if (lp.nodelay)
    {
      ret = set_nodelay (fd, 1);
      if (ret)
        LP_ERR2 (worker, LP_FAILED, LP_E_NODELAY, errno);
    }

  if (!lp.block_connecting)
    {
      ret = set_nonblock (fd);
      if (ret)
        {
          LP_ERR2 (worker, LP_FAILED, LP_E_NONBLOCK, errno);
          return -1;
        }
#if 1
      ret = lp_epadd (worker, fd, EPOLLOUT);
      if (ret)
        {
          LP_ERR2 (worker, LP_FAILED, LP_E_EPADD, errno);
          DBG ("->epoll_ctl(%d, ADD, %d)=%d:%d", worker->epfd, fd, ret,
               errno);
          return -1;
        }
      return 1;
#endif
    }

  return 0;
}

int
lp_connected (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  struct timespec now;
  struct lp_test *test;

  LB_TIME (now);
  LP_TIME_FOR (worker, LP_W_CONNECTED, sess->time, now);
  sess->time = now;

  LP_APPEND (worker->sess, fd, sess, sess);
  sess->state = LP_S_CONNECTED;
  LP_CNT (worker, LP_CONNECTED);

  test = &lp.test[sess->test];
  if (test->query)
    {
      if (lp.block_connecting && set_nonblock (fd))
        {
          LP_ERR (worker, LP_E_NONBLOCK, errno);
          return -1;
        }
      if (sess->epout)
        {
          if (lp_epmod (worker, fd, EPOLLIN))
            {
              LP_ERR (worker, LP_E_EPMOD, errno);
              return -1;
            }
          sess->epout = 0;
        }
      else
        {
          if (lp_epadd (worker, fd, EPOLLIN))
            {
              LP_ERR (worker, LP_E_EPADD, errno);
              return -1;
            }
        }
      sess->io_num = test->times;

      if (test->wait)
        {
          sess->time.tv_sec += test->wait;
          lp_add_wait (worker, fd, sess);
          return 0;
        }

      return lp_new_query (worker, fd, sess);
    }

  if (sess->epout)
    {
      if (lp_epdel (worker, fd))
        LP_ERR (worker, LP_E_EPDEL, errno);
      sess->epout = 0;
    }

  return 0;
}

int
lp_connect (struct lp_worker *worker, int cid, int sid, int test_id)
{
  int ret, fd;
  struct lp_sess *sess;
  struct timespec connect_begin;

  LP_TIME_SET (begin);
  fd = _socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0)
    {
      LP_ERR2 (worker, LP_FAILED, LP_E_SOCKET, errno);
      DBG ("->socket(...)=%d:%d\n", fd, errno);
      return -1;
    }
  LP_TIME_END (worker, LP_W_SOCKET, begin);

  ret = lp_pre_connect (worker, fd, worker->client_addr + cid);
  if (ret < 0)
    {
      _close (fd);
      return -1;
    }

  LB_TIME (connect_begin);
  ret =
    _connect (fd, (struct sockaddr *) (worker->server_addr + sid),
              sizeof (struct sockaddr_in));
  LP_TIME_END (worker, LP_W_CONNECT, connect_begin);

  if (ret)
    {
      const int e = errno;
      if (lp.block_connecting || e != EINPROGRESS)
        {
          LP_ERR2 (worker, LP_FAILED, LP_E_CONNECT, e);
          DBG ("->connect(%d, %s)=%d:%d\n", fd,
               f_inaddr (worker->server_addr + sid), ret, e);
          _close (fd);
          return -1;
        }
    }

  LP_TIME_END (worker, LP_W_CREATE, begin);
  LP_CNT (worker, LP_CONNECT);

  sess = lp_init_sess (worker, fd);
  sess->test = test_id;
  sess->time = connect_begin;
  if (!lp.block_connecting)
    sess->epout = 1;

  if (ret)
    {
      /* nonblock connect inprogress */
      lp_add_conn (worker, fd, sess);
      return 1;
    }

  ret = lp_connected (worker, fd, sess);
  if (ret < 0)
    lp_del_sess (worker, fd);

  return ret;
}

inline static int
lp_handle_client (struct lp_worker *worker, int fd, uint32_t events)
{
  struct lp_sess *sess = LP_SESS (fd);

  if (sess->state == LP_S_UNUSED)
    {
      LP_CNT (worker, LP_E_EPUNUSED);
      return 0;
    }

  if (events & EPOLLRDHUP)
    {
      LP_CNT (worker, LP_E_EPHUP);
      return -1;
    }

  if (events & EPOLLERR)
    {
      LP_CNT (worker, LP_E_EPERR);
      DBG ("epoll event error, fd:%d event:0x%x\n", fd, events);
      return -1;
    }

  if (events & EPOLLIN)
    {
      if (sess->state == LP_S_REPLY)
        return lp_recv_reply (worker, fd, sess);
      LP_CNT (worker, LP_E_EPERR);
      return 0;
    }

  if (events & EPOLLOUT)
    {
      if (sess->state == LP_S_CONNECTING)
        {
          lp_out_conn (worker, fd, sess);
          return lp_connected (worker, fd, sess);
        }
      if (sess->state == LP_S_QUERY)
        return lp_more_query (worker, fd, sess);
      LP_CNT (worker, LP_E_EPERR);
      return 0;
    }

  LP_CNT (worker, LP_E_EPEVENT);
  return -1;
}

inline static void
lp_init_mode (const struct lp_worker *worker, int *cid, int *sid)
{
  if (worker->link_mode == LP_RAND)
    {
      *cid = LB_RAND (worker->client_num);
      *sid = LB_RAND (worker->server_num);
    }
  else
    {
      *cid = 0;
      *sid = 0;
    }
}

inline static void
lp_next_mode (const struct lp_worker *worker, int *cid, int *sid)
{
  if (worker->link_mode == LP_RAND)
    {
      *cid = LB_RAND (worker->client_num);
      *sid = LB_RAND (worker->server_num);
    }
  else if (worker->link_mode == LP_SYNC)
    {
      if (++*sid >= worker->server_num)
        *sid = 0;
      if (++*cid >= worker->client_num)
        *cid = 0;
    }
  else if (worker->link_mode == LP_CPS)
    {
      if (++*cid >= worker->client_num)
        {
          *cid = 0;
          if (++*sid >= worker->server_num)
            *sid = 0;
        }
    }
  else if (worker->link_mode == LP_SPC)
    {
      if (++*sid >= worker->server_num)
        {
          *sid = 0;
          if (++*cid >= worker->client_num)
            *cid = 0;
        }
    }
  else
    {
      err ("Error mode value:%d\n", worker->link_mode);
    }
}

void
lp_client (struct lp_worker *worker)
{
  int ret, num = 0, cid, sid, test_id = -1;
  struct epoll_event *event;
  struct lp_test *test = &lp.test[0];
  struct lb_run *up = worker->up_run;
  struct lb_run *down = worker->down_run;
  const int epfd = worker->epfd;

  lp_init_mode (worker, &cid, &sid);

  while (lp.run_state == LP_EXEC)
    {
      int i;
      struct timespec now;

      if (test_id != lp.test_id)
        {
          DBG ("worker %d change test_id %d\n", worker->index, lp.test_id);
          test = &lp.test[test_id = lp.test_id];

          if (test->up)
            run_init (up, (test->up + lp.worker_num - 1) / lp.worker_num,
                      LP_UP_SLOT, LP_UP_NSEC);
          if (test->down)
            run_init (down, (test->down + lp.worker_num - 1) / lp.worker_num,
                      LP_DOWN_SLOT, LP_DOWN_NSEC);
        }

      LB_TIME (now);

      /* up process */
      if (test->up)
        {
          if (run_test (up, &now) > 0)
            {
              ret = lp_connect (worker, cid, sid, test_id);
              if (ret >= 0)
                run_add (up, 1);
              lp_next_mode (worker, &cid, &sid);
              LB_TIME (now);
            }
        }

      /* down process */
      if (test->down && worker->sess.num)
        {
          if (run_test (down, &now) > 0)
            {
              lp_del_sess (worker, worker->sess.first);
              run_add (down, 1);
              LB_TIME (now);
            }
        }

      /* query */
      for (i = 0; i <= test_id; ++i)
        {
          int fd;
          struct lp_sess *sess;

          if (worker->rest[i].num)
            {
              fd = worker->rest[i].first;
              sess = LP_SESS (fd);
              if (LB_CMP (now, sess->time) >= 0)
                {
                  LP_ASSERT (sess->state == LP_S_REST);
                  LP_ASSERT (sess->test == i);
                  lp_out_rest (worker, fd, sess);
                  if (lp_new_query (worker, fd, sess) < 0)
                    {
                      lp_del_sess (worker, fd);
                      if (test->down)
                        run_add (down, 1);
                    }
                  LB_TIME (now);
                }
            }
          if (worker->wait[i].num)
            {
              fd = worker->wait[i].first;
              sess = LP_SESS (fd);
              if (LB_CMP (now, sess->time) >= 0)
                {
                  LP_ASSERT (sess->state == LP_S_WAIT);
                  LP_ASSERT (sess->test == i);
                  lp_out_wait (worker, fd, sess);
                  if (lp_new_query (worker, fd, sess) < 0)
                    {
                      lp_del_sess (worker, fd);
                      if (test->down)
                        run_add (down, 1);
                    }
                  LB_TIME (now);
                }
            }
        }

      /* check connect timeout */
      if (worker->conn.first >= 0)
        {
        }

      /* epoll event process */
      if (num > 0)
        {
          const uint64_t type = LP_EV_TYPE (event->data.u64);
          const int fd = LP_EV_FD (event->data.u64);

          if (type == LP_SESSION_TYPE)
            {
              if (lp_handle_client (worker, fd, event->events) < 0)
                {
                  struct lp_sess *sess = LP_SESS (fd);
                  if (sess->state & LP_S_CONNECTED)
                    {
                      lp_del_sess (worker, fd);
                      if (test->down)
                        run_add (down, 1);
                    }
                  else if (sess->state == LP_S_CONNECTING)
                    {
                      lp_del_conn (worker, fd, sess);
                    }
                  else
                    {
                    }
                }
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
          num = _epoll_wait (epfd, worker->ev_buf, LP_EVENT_NUM, 0);
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
