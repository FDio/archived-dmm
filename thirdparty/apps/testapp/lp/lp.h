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

#ifndef _LP_H_
#define _LP_H_ 1

#define LP_DBG 1

#if LP_DBG
#define LP_IF_DBG(line) line
#else
#define LP_IF_DBG(line) ((void)0)
#endif

#define LP_ASSERT(cond) LP_IF_DBG(assert(cond))

#define LP_DELAY_MS 5
#define LP_LOOP_TIMER (49 * 1000 * 1000)
#define LP_LOOP_REST (900 * 1000 * 1000)

#define LP_UP_SLOT 1024
#define LP_UP_NSEC (1000 * 1000)

#define LP_DOWN_SLOT 1024
#define LP_DOWN_NSEC (1000 * 1000)

#define LP_MAX_FD (16 * 1024 * 1024)
#define LP_MAX_WORKER 64
#define LP_MAX_TEST 10

#define LP_IOBUF_SIZE (128 * 1024)

#define LP_EVENT_NUM 256

#define LP_SERVER_MAX 10000
#define LP_CLIENT_MAX 100000

#define LP_INFINITE  (0xFFFFffff)
#define LP_UNLIMITED LP_INFINITE
#define LP_VALUE_MAX (LP_INFINITE - 1)

#define LP_INTERVAL_MIN 1
#define LP_INTERVAL_MAX 60
#define LP_INTERVAL_DEF 1

#define LP_TARGET_INF LP_INFINITE
#define LP_TARGET_MAX (16 * 1000 * 1000)        /* 16m max */
#define LP_TARGET_DEF LP_INFINITE

#define LP_TIME_INF LP_INFINITE
#define LP_TIME_MAX (24 * 60 * 60)
#define LP_TIME_DEF LP_TIME_INF

#define LP_UP_MAX ( 1 * 1000 * 1000)
#define LP_UP_INF LP_INFINITE
#define LP_UP_DEF 0

#define LP_DOWN_MAX (1 * 1000 * 1000)
#define LP_DOWN_INF LP_INFINITE
#define LP_DOWN_DEF 0

#define LP_QUERY_MIN 8          /* 2 unsigned int */
#define LP_QUERY_MAX 65536

#define LP_REPLY_MAX (10 * 1024 * 1024) /* 10M */

#define LP_TIMES_INF LP_INFINITE
#define LP_TIMES_MAX LP_VALUE_MAX
#define LP_TIMES_DEF LP_TIMES_INF

#define LP_PERIOD_MIN 1
#define LP_PERIOD_MAX (60 * 60)
#define LP_PERIOD_DEF 1

#define LP_WAIT_MAX (60 * 60)
#define LP_WAIT_DEF 0

#define LP_FLAG_MASK	(0xffffFFFFull << 32)
#define LP_TYPE_MASK	(0x3ull << 32)
#define LP_CONTROL_TYPE	(0x1ull << 32)
#define LP_LISTEN_TYPE	(0x2ull << 32)
#define LP_SESSION_TYPE	(0x3ull << 32)

inline static uint64_t
LP_EV_MK (uint64_t flag, int fd)
{
  return flag | (uint64_t) (uint32_t) fd;
}

inline static int
LP_EV_FD (uint64_t data_u64)
{
  return (int) (uint32_t) data_u64;
}

inline static uint64_t
LP_EV_TYPE (uint64_t data_u64)
{
  return data_u64 & LP_TYPE_MASK;
}

inline static uint64_t
LP_EV_FLAG (uint64_t data_u64)
{
  return data_u64 & LP_FLAG_MASK;
}

#define LP_R_SIGN 1
#define LP_E_SIGN 2
#define LP_W_SIGN 4
#define LP_ERR_SIGN 8

enum
{
  LP_CONNECTED,
  LP_CONNECT,
  LP_CLOSE,
  LP_FAILED,

  LP_QUERY_COMP,
  LP_QUERY_BYTE,
  LP_REPLY_COMP,
  LP_REPLY_BYTE,

  LP_REC_NUM,

  LP_R_END,
  LP_E_BEGIN = LP_R_END,

  LP_E_SOCKET = LP_E_BEGIN,
  LP_E_BIND,
  LP_E_ACCEPT,
  LP_E_CONNECT,
  LP_E_NODELAY,
  LP_E_NONBLOCK,
  LP_E_REUSEADDR,
  LP_E_REUSEPORT,
  LP_E_RECV,
  LP_E_SEND,

  LP_E_EPADD,
  LP_E_EPMOD,
  LP_E_EPDEL,
  LP_E_EPWAIT,
  LP_E_EPUNUSED,
  LP_E_EPHUP,
  LP_E_EPERR,
  LP_E_EPINOUT,
  LP_E_EVIDLE,
  LP_E_EPEVENT,

  LP_E_IOSHUT,
  LP_E_IOSIZE,
  LP_E_IOMORE,
  LP_E_IOEXCEED,
  LP_E_IOSEND0,

  LP_E_END,
  LP_W_BEGIN = LP_E_END,

  LP_W_CREATE = LP_W_BEGIN, LP_T_CREATE,
  LP_W_SOCKET, LP_T_SOCKET,
  LP_W_BIND, LP_T_BIND,
  LP_W_CONNECT, LP_T_CONNECT,
  LP_W_CONNECTED, LP_T_CONNECTED,
  LP_W_ACCEPT, LP_T_ACCEPT,
  LP_W_CLOSE, LP_T_CLOSE,

  LP_W_END,

  LP_CNT_NUM = LP_W_END
};

#define LP_ERRNO_NUM 256
#define LP_NOERR_NUM ((LP_ERRNO_NUM + 63) / 64)

struct lp_stat
{
  uint64_t cnt[LP_CNT_NUM];
  uint64_t err[LP_ERRNO_NUM];
};

#define LP_STAT(worker) (lp.curr + (worker)->index)
#define LP_ADD(worker, id, num) (LP_STAT(worker)->cnt[(id)] += (num))
#define LP_CNT(worker, id) (++LP_STAT(worker)->cnt[(id)])
#define LP_ERR(worker, id, e) do { \
	unsigned int _e = (unsigned int)(e); \
	if (_e >= LP_ERRNO_NUM) \
		_e = 0; \
	if (0 == (lp.no_err[_e / 64] & (1 << (_e % 64)))) { \
		struct lp_stat *_stat = LP_STAT(worker); \
		_stat->cnt[(id)]++; \
		_stat->err[_e]++; \
	} \
} while (0)
#define LP_CNT2(worker, id1, id2) do { \
	struct  lp_stat *_stat = LP_STAT(worker); \
	_stat->cnt[(id1)]++; \
	_stat->cnt[(id2)]++; \
} while (0)
#define LP_ERR2(worker, id1, id2, e) do { \
	unsigned int _e = (unsigned int)(e); \
	if (_e >= LP_ERRNO_NUM) \
		_e = 0; \
	if (0 == (lp.no_err[_e / 64] & (1 << (_e % 64)))) { \
		struct lp_stat *_stat = LP_STAT(worker); \
		_stat->cnt[(id1)]++; \
		_stat->cnt[(id2)]++; \
		_stat->err[_e]++; \
	} \
} while (0)

#define LP_TIME_SET(begin) struct timespec begin; \
	do { \
		if (lp.watch) \
			LB_TIME(begin); \
	} while (0)
#define LP_TIME_REG(worker, id, nsec) do { \
	if (lp.watch) { \
		uint64_t *_w = &(LP_STAT(worker)->cnt[(id)]); \
		_w[0] ++; \
		_w[1] += nsec; \
	} \
} while (0)
#define LP_TIME_FOR(worker, id, begin, end) LP_TIME_REG((worker), (id), LB_SUB_NS((end), (begin)))
#define LP_TIME_END(worker, id, begin) do { \
	LP_TIME_SET(_end); \
	LP_TIME_FOR((worker), (id), (begin), _end); \
} while (0)

struct lp_io
{
  int query;
  int reply;
} __attribute__ ((__packed__));

struct lp_head
{
  uint32_t num;
  int first;
  int *last;
};

enum
{
  LP_S_UNUSED = 0,
  LP_S_PREPARE = 0x20,
  LP_S_CONNECTING = 0x80,

  LP_S_CONNECTED = 0x10,

  LP_S_IDLE = LP_S_CONNECTED | 0,
  LP_S_QUERY = LP_S_CONNECTED | 1,
  LP_S_REPLY = LP_S_CONNECTED | 2,
  LP_S_REST = LP_S_CONNECTED | 4,
  LP_S_WAIT = LP_S_CONNECTED | 8,
};

struct lp_sess
{
  uint8_t state;
  uint8_t test;
  uint8_t epout;
  uint32_t io_num;
  int query;
  int reply;

  int *prev_sess;
  int next_sess;
  int next_rest;
  int *prev_rest;
  struct timespec time;

#if LP_DBG
  uint16_t work;
  uint16_t anum;
  uint16_t fnum;
#endif
};

struct lp_test
{
  uint32_t target;
  uint32_t time;

  uint32_t up;
  uint32_t down;

  int query;
  int reply;

  uint32_t times;
  uint32_t period;
  uint32_t wait;

  uint8_t down_mode;
  uint8_t close_after_io;
  uint8_t _pad[2];
};

enum
{
  LP_SYNC,
  LP_RAND,
  LP_CPS,
  LP_SPC,
};

struct lp_worker
{
  int index;
  int epfd;
  int ctlfd;
  int server_num;
  int client_num;
  int link_mode;

  pthread_t tid;

  struct lp_head server;
  struct lp_head sess;          /* ESTABLISHED */
  struct lp_head conn;          /* connecting(for nonblock of client) */
  struct lp_head rest[LP_MAX_TEST];     /* io wait queue */
  struct lp_head wait[LP_MAX_TEST];     /* io wait queue */

  struct sockaddr_in *server_addr;
  struct sockaddr_in *client_addr;

  struct lb_run *up_run;
  struct lb_run *down_run;

  struct epoll_event *ev_buf;

  void *io_buf;
};

enum lp_state
{
  LP_EXIT = -1,
  LP_INIT = 0,
  LP_EXEC = 1,
  LP_CLEAN = 2,
};

struct lp_var
{
  int CPU_NUM;
  volatile int run_state;
  int worker_num;

  uint8_t verbose;
  uint8_t watch;
  uint8_t err_msg;
  uint8_t _pad;

  int client_mode;
  int block_connecting;

  int interval;
  int nodelay;

  int test_num;
  volatile int test_id;

  uint64_t core;
  uint64_t active_worker;

  struct lp_sess *sess;
  struct lp_stat *volatile curr;
  struct lp_stat *next;
  struct lp_stat stat[2][LP_MAX_WORKER];
  struct lp_test test[LP_MAX_TEST];
  struct lp_worker worker[LP_MAX_WORKER];
  uint64_t no_err[LP_NOERR_NUM];
};

extern struct lp_var lp;

inline static struct lp_worker *
LP_WORKER (int index)
{
  return &lp.worker[index];
}

inline static struct lp_sess *
LP_SESS (int fd)
{
  return lp.sess + fd;
}

inline static uint64_t
lp_total_sess ()
{
  int i;
  uint64_t total = 0;
  for (i = 0; i < lp.worker_num; ++i)
    total += lp.worker[i].sess.num;
  return total;
}

#define LP_APPEND(head, fd, sess, name) do { \
	struct lp_sess *_s = (sess); \
	LP_ASSERT(_s->next_##name == fd); \
	LP_ASSERT(_s->prev_##name == NULL); \
	_s->next_##name = -1; \
	_s->prev_##name = (head).last; \
	*(head).last = fd; \
	(head).last = &_s->next_##name; \
	(head).num++; \
} while (0)

#define LP_REMOVE(head, fd, sess, name) do { \
	struct lp_sess *_s = (sess); \
	LP_ASSERT((head).num); \
	if ((*_s->prev_##name = _s->next_##name) >= 0) \
		LP_SESS(_s->next_##name)->prev_##name = _s->prev_##name; \
	else \
		(head).last = _s->prev_##name; \
	(head).num--; \
	LP_IF_DBG(_s->next_##name = (fd)); \
	LP_IF_DBG(_s->prev_##name = NULL); \
} while (0)

inline static void
lp_init_head (struct lp_head *head)
{
  head->first = -1;
  head->num = 0;
  head->last = &head->first;
}

inline static void
lp_dest_sess (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  LP_ASSERT (sess->next_rest == fd);
  LP_ASSERT (sess->next_sess == fd);
  LP_ASSERT (sess->prev_rest == NULL);
  LP_ASSERT (sess->prev_sess == NULL);
  LP_ASSERT (sess->work == worker->index);
#if LP_DBG
  sess->fnum++;
#endif
  LP_ASSERT (sess->fnum == sess->anum);

  sess->state = LP_S_UNUSED;
}

inline static struct lp_sess *
lp_init_sess (struct lp_worker *worker, int fd)
{
  struct lp_sess *sess = LP_SESS (fd);

  if (sess->state != LP_S_UNUSED)
    {
      void lp_dump_sess (int fd);
      wrn ("Invalid session fd:%d\n", fd);
#if LP_DBG
      lp_dump_sess (fd);
#endif
      LP_ASSERT (0);
    }
  LP_ASSERT (sess->fnum == sess->anum);

  sess->state = LP_S_PREPARE;
  sess->epout = 0;
  sess->io_num = 0;
  sess->query = 0;
  sess->reply = 0;

#if LP_DBG
  sess->work = worker->index;
  sess->anum++;
  sess->next_rest = sess->next_sess = fd;
  sess->prev_rest = sess->prev_sess = NULL;
#endif

  return sess;
}

inline static void
lp_add_conn (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  LP_ASSERT (sess->state == LP_S_PREPARE);

  LP_APPEND (worker->conn, fd, sess, sess);
  sess->state = LP_S_CONNECTING;
}

inline static void
lp_out_conn (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  LP_ASSERT (worker->conn.num);
  LP_ASSERT (sess->state == LP_S_CONNECTING);

  LP_REMOVE (worker->conn, fd, sess, sess);
}

inline static void
lp_del_conn (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  lp_out_conn (worker, fd, sess);
  lp_dest_sess (worker, fd, sess);
  _close (fd);
}

inline static void
lp_add_rest (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  LP_APPEND (worker->rest[sess->test], fd, sess, rest);
  sess->state = LP_S_REST;
}

inline static void
lp_out_rest (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  LP_ASSERT (worker->rest[sess->test].num);

  LP_REMOVE (worker->rest[sess->test], fd, sess, rest);
  sess->state = LP_S_IDLE;
}

inline static void
lp_add_wait (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  LP_APPEND (worker->wait[sess->test], fd, sess, rest);
  sess->state = LP_S_WAIT;
}

inline static void
lp_out_wait (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  LP_ASSERT (worker->wait[sess->test].num);

  LP_REMOVE (worker->wait[sess->test], fd, sess, rest);
  sess->state = LP_S_IDLE;
}

inline static void
lp_del_sess (struct lp_worker *worker, int fd)
{
  struct lp_sess *sess = LP_SESS (fd);

  LP_ASSERT (sess->state & LP_S_CONNECTED);

  if (sess->state == LP_S_REST)
    lp_out_rest (worker, fd, sess);
  else if (sess->state == LP_S_WAIT)
    lp_out_wait (worker, fd, sess);
  LP_REMOVE (worker->sess, fd, sess, sess);

  lp_dest_sess (worker, fd, sess);
  LP_TIME_SET (begin);
  _close (fd);
  LP_TIME_END (worker, LP_W_CLOSE, begin);

  LP_CNT (worker, LP_CLOSE);
}

inline static int
lp_epctl (const struct lp_worker *worker, int op, int fd, uint32_t io)
{
  struct epoll_event event;
  event.events = io | EPOLLET | EPOLLRDHUP | EPOLLHUP;
  event.data.u64 = LP_EV_MK (LP_SESSION_TYPE, fd);
  return _epoll_ctl (worker->epfd, op, fd, &event);
}

#define lp_epadd(worker, fd, io) lp_epctl((worker), EPOLL_CTL_ADD, (fd), (io))
#define lp_epmod(worker, fd, io) lp_epctl((worker), EPOLL_CTL_MOD, (fd), (io))
#define lp_epdel(worker, fd) _epoll_ctl((worker->epfd), EPOLL_CTL_DEL, (fd), NULL)

inline static int
lp_set_epout (struct lp_worker *worker, int fd, struct lp_sess *sess)
{
  if (sess->epout)
    return 1;

  if (lp_epmod (worker, fd, EPOLLOUT))
    {
      LP_ERR (worker, LP_E_EPMOD, errno);
      return -1;
    }

  sess->epout = 1;
  return 1;
}

#define LP_CMD_STOP 1

inline static int
lp_post_cmd (int fd, long long int cmd)
{
  ssize_t ret = _write (fd, (void *) &cmd, sizeof (cmd));

  return ret - sizeof (cmd);
}

void lp_client (struct lp_worker *worker);
void lp_server (struct lp_worker *worker);
int lp_listen (struct lp_worker *worker, int index);

#endif /* #ifndef _LP_H_ */
