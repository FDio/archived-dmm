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

#ifndef _CPS_H_
#define _CPS_H_

#define CPS_FRAG_NUM 64
#define CPS_FRAG_NS (20 * 1000 * 1000)  /* 20 ms */
#define CPS_FRAG_LOOP (CPS_FRAG_NS * CPS_FRAG_NUM)      /* 1.28 s */

#define CPS_TIMER_MS 100
#define CPS_DELAY_MS 5

#define CPS_MAX_FD (16 * 1024 * 1024)   /* 10M */
#define CPS_CONN_MAX (256 * 1024)

#define CPS_EPSIZE (1 * 1000)   /* =1k */
#define CPS_EPWAIT_MS 200       /* ms */

#define CPS_THREAD_MAX 128
#define CPS_SERVER_MAX 32
#define CPS_CLIENT_MAX 256
#define CPS_CLIENT_IAS_MAX 32

#define CPS_PORT_DEF 58166
#define CPS_EVNUM_DEF 256
#define CPS_EVNUM_MAX 1024
#define CPS_TIME_DEF 300
#define CPS_TIME_MAX (60 * 60 * 24 * 7) /* 604800s = 1 week */
#define CPS_RATE_DEF 10000      /* 1w */
#define CPS_RATE_MAX (100 * 1000 * 1000)        /* 100m */
#define CPS_REQ_DEF 1
#define CPS_RES_DEF 1
#define CPS_DATA_MAX 4096
#define CPS_INTERVAL_DEF 10     /* s */
#define CPS_INTERVAL_MAX 3600   /* s */

#define CPS_ERR_NUM 256

#define CPS_CONN_SID (-1)
#define CPS_EV_DATA(sid, fd) (((uint64_t)(uint32_t)(sid) << 32) | (uint64_t)(uint32_t)(fd))
#define CPS_EV_FD(u64) ((int)(uint32_t)(u64))
#define CPS_EV_SID(u64) ((int)(uint32_t)((u64) >> 32))

enum
{
  CPS_LOOP_BOTH = 0,
  CPS_LOOP_CF,
  CPS_LOOP_SF,
};

enum
{
  CPS_ERROR = -2,
  CPS_EXIT = -1,

  CPS_INIT = 0,

  CPS_RUNNING = 1,
  CPS_CLOSING = 2,
};

enum
{
  CPS_CNT_CONN_MAX,
  CPS_CNT_CONN_NUM,

  CPS_CNT_GTFD,
  CPS_CNT_SOCKET_ERR,
  CPS_CNT_BIND_ERR,
  CPS_CNT_ACCEPT_ERR,
  CPS_CNT_CONNECT_ERR,
  CPS_CNT_REUSEADDR_ERR,
  CPS_CNT_NODELAY_ERR,
  CPS_CNT_NONBLOCK_ERR,
  CPS_CNT_SEND_ERR,
  CPS_CNT_RECV_ERR,
  CPS_CNT_EPOLL_ERR,
  CPS_CNT_ERR_EVENT,
  CPS_CNT_FD_ERR,

  CPS_CNT_NUM
};

#define CPS_CNT_ITEM(thread, id) (cps.curr[(thread)->index].cnt[(id)])

#define CPS_CNT_INC(thread, id) (++CPS_CNT_ITEM((thread), (id)))
#define CPS_CNT_INC_E(thread, id, e) do { \
	struct cps_stat *_stat = cps.curr + (thread)->index; \
	++_stat->cnt[(id)]; \
	if ((e) >= CPS_ERR_NUM) ++_stat->err[0];\
	else ++_stat->err[(e)]; \
} while(0)

enum
{
  CPS_REC_INIT,

  CPS_REC_CONN,
  CPS_REC_CONN_TIME,

  CPS_REC_RECV,
  CPS_REC_RECV_TIME,

  CPS_REC_SEND,
  CPS_REC_SEND_TIME,

  CPS_REC_FAIL,

  CPS_REC_NUM
};

#define CPS_REC_INC(thread, id) (++cps.curr[(thread)->index].rec[(id)])

#define CPS_REC_TIMED_INC(thread, id, last) do { \
	struct timespec _time; \
	struct cps_stat *_stat = cps.curr + (thread)->index; \
	LB_TIME(_time); \
	_stat->rec[(id)]++; \
	_stat->rec[(id) + 1] += LB_SUB_NS(_time, (last)); \
	(last) = _time; \
} while (0)

struct cps_conn
{
  union
  {
    int size;
    int sid;
  };
  int next;
  int *prev;
  struct timespec last;

  struct timespec create_time;
};

struct cps_stat
{
  uint64_t cnt[CPS_CNT_NUM];
  uint64_t rec[CPS_REC_NUM];
  uint64_t err[CPS_ERR_NUM];
};

struct cps_thread
{
  int epfd;
  int index;
  int core;
  int loop;

  int server;
  int conn;
  int conn_num;

  int server_num;
  int client_num;
  int c_addr_num;

  uint64_t rate;
  pthread_t tid;

  struct sockaddr_in s_addr[CPS_SERVER_MAX];
  struct inaddrs c_addr[CPS_CLIENT_MAX];
  struct epoll_event event[CPS_EVNUM_MAX];
};

struct cps_var
{
  int run_state;
  int CPU_NUM;

  int verbose;
  int more;
  int client;
  int evnum;

  int req_len;
  int res_len;

  int test_time;
  int interval;

  int active_thread;
  int thread_num;
  int server_num;
  int client_num;

  uint64_t rate;

  struct cps_stat *curr;
  struct cps_stat *next;

  struct cps_conn *conn;
  struct cps_thread *thread[CPS_THREAD_MAX];

  struct cps_stat records[2][CPS_THREAD_MAX];
};

extern struct cps_var cps;

inline static struct cps_conn *
CPS_CONN (int fd)
{
  return cps.conn + fd;
}

inline static void
cps_add_server (struct cps_thread *thread, int fd, int sid)
{
  struct cps_conn *conn = CPS_CONN (fd);

  conn->sid = sid;
  conn->next = thread->server;
  conn->prev = &thread->server;
  LB_TIME (conn->last);
  if (thread->server >= 0)
    CPS_CONN (thread->server)->prev = &conn->next;
  thread->server = fd;
}

inline static void
cps_add_conn (struct cps_thread *thread, int fd, int size,
              struct timespec *begin)
{
  struct cps_conn *conn = CPS_CONN (fd);

  conn->size = size;
  conn->last = *begin;
  conn->next = thread->conn;
  conn->prev = &thread->conn;
  if (thread->conn >= 0)
    CPS_CONN (thread->conn)->prev = &conn->next;
  thread->conn = fd;

  if (++thread->conn_num > CPS_CNT_ITEM (thread, CPS_CNT_CONN_MAX))
    CPS_CNT_ITEM (thread, CPS_CNT_CONN_MAX) = thread->conn_num;
  CPS_REC_TIMED_INC (thread, CPS_REC_CONN, conn->last);
}

inline static void
cps_rem_conn (struct cps_thread *thread, int fd, struct cps_conn *conn)
{
  --thread->conn_num;

  *conn->prev = conn->next;
  if (conn->next >= 0)
    CPS_CONN (conn->next)->prev = conn->prev;
}

inline static struct cps_thread *
cps_new_thread ()
{
  struct cps_thread *thread = calloc (1, sizeof (struct cps_thread));

  if (thread)
    {
      thread->index = cps.thread_num;
      thread->epfd = -1;
      thread->core = -1;
      thread->conn = -1;
      thread->server = -1;

      cps.thread[cps.thread_num++] = thread;
    }

  return thread;
}

#endif /* #ifndef _CPS_H_ */
