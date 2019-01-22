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

void *cps_s_thread (void *arg);
void *cps_c_thread (void *arg);

static const char *const cps_stat_name[CPS_CNT_NUM] = {
  [CPS_CNT_CONN_MAX] = "max",
  [CPS_CNT_CONN_NUM] = "conn",

  [CPS_CNT_GTFD] = "GREATER-THAN-MAX-FD",
  [CPS_CNT_SOCKET_ERR] = "socket-err",
  [CPS_CNT_BIND_ERR] = "bind-err",
  [CPS_CNT_CONNECT_ERR] = "connect-err",
  [CPS_CNT_REUSEADDR_ERR] = "reuseaddr-err",
  [CPS_CNT_NODELAY_ERR] = "nodelay-err",
  [CPS_CNT_NONBLOCK_ERR] = "nonblock-err",
  [CPS_CNT_ACCEPT_ERR] = "accept-err",
  [CPS_CNT_SEND_ERR] = "send-err",
  [CPS_CNT_RECV_ERR] = "recv-err",
  [CPS_CNT_EPOLL_ERR] = "epoll-err",
  [CPS_CNT_ERR_EVENT] = "err-event",
  [CPS_CNT_FD_ERR] = "cid-err",
};

struct cps_var cps = { 0 };

void
cps_title ()
{
  out ("------------------------------------------------------------\n");
  out (" cps test %s\n", cps.client ? "client" : "server");
  out
    (" total server: %d  total thread: %d  report interval: %ds  request:%d  response: %d  CPU NUM: %d\n",
     cps.server_num, cps.thread_num, cps.interval, cps.req_len, cps.res_len,
     cps.CPU_NUM);
  if (cps.client)
    {
      out (" total client: %d  test time: %ds defalut rate:%lu\n",
           cps.client_num, cps.test_time, cps.rate);
    }
  else
    {
    }
  out ("------------------------------------------------------------\n");
}

inline static char *
cps_tip (char *pos, char tip)
{
  *pos++ = '|';
  *pos++ = tip;
  *pos++ = ':';
  *pos++ = ' ';
  return pos;
}

inline static char *
cps_fmt (char *pos, uint64_t val, int *size)
{
  int s = r_uint (pos, val, *size);
  pos += s;
  *pos++ = ' ';
  if (s > *size)
    *size = s;
  return pos;
}

inline static char *
cps_format (char *pos, char tip, uint64_t val, uint64_t nsec, int *size)
{
  pos = cps_tip (pos, tip);

  if (cps.more)
    pos = cps_fmt (pos, val, size);

  pos = cps_fmt (pos, lb_gdiv (val, nsec), size + 1);

  return pos;
}

void
cps_output (int index, struct cps_stat *stat, uint64_t nsec)
{
  struct fmtsize
  {
    int s_init[2];
    int s_conn[3];
    int s_recv[3];
    int s_send[3];
    int s_fail[2];
  };
  static struct fmtsize size = { 0 };
  static int space_line = 0;
  static char buf[512];

  char *pos = buf;
  int i, cnt_num = 0;

  if (!stat->rec[CPS_REC_INIT] && !stat->rec[CPS_REC_CONN] &&
      !stat->rec[CPS_REC_RECV] && !stat->rec[CPS_REC_SEND]
      && !stat->rec[CPS_REC_FAIL])
    {
      for (i = 0; i < CPS_CNT_NUM; ++i)
        {
          if (stat->cnt[i])
            break;
        }
      if (i >= CPS_CNT_NUM)
        {
          if (index < 0 && space_line++ == 0)
            {
              out ("\n");
              memset (&size, 0, sizeof (size));
            }
          return;
        }
    }

  space_line = 0;

  if (index < 0)
    pos += sprintf (pos, " sum ");
  else
    pos += sprintf (pos, " %3d ", index);

  pos =
    cps_format (pos, (cps.client ? 'C' : 'A'), stat->rec[CPS_REC_INIT], nsec,
                size.s_init);
  pos = cps_format (pos, 'E', stat->rec[CPS_REC_CONN], nsec, size.s_conn);
  if (cps.client)
    {
      pos = cps_format (pos, 'S', stat->rec[CPS_REC_SEND], nsec, size.s_send);
      pos = cps_format (pos, 'R', stat->rec[CPS_REC_RECV], nsec, size.s_recv);
    }
  else
    {
      pos = cps_format (pos, 'R', stat->rec[CPS_REC_RECV], nsec, size.s_recv);
      pos = cps_format (pos, 'S', stat->rec[CPS_REC_SEND], nsec, size.s_send);
    }
  pos = cps_format (pos, 'F', stat->rec[CPS_REC_FAIL], nsec, size.s_fail);

  pos = cps_tip (pos, 'T');
  pos =
    cps_fmt (pos,
             lb_sdiv (stat->rec[CPS_REC_CONN_TIME], stat->rec[CPS_REC_CONN]),
             &size.s_conn[2]);
  if (cps.client)
    {
      pos =
        cps_fmt (pos,
                 lb_sdiv (stat->rec[CPS_REC_SEND_TIME],
                          stat->rec[CPS_REC_SEND]), &size.s_send[2]);
      pos =
        cps_fmt (pos,
                 lb_sdiv (stat->rec[CPS_REC_RECV_TIME],
                          stat->rec[CPS_REC_RECV]), &size.s_recv[2]);
    }
  else
    {
      pos =
        cps_fmt (pos,
                 lb_sdiv (stat->rec[CPS_REC_RECV_TIME],
                          stat->rec[CPS_REC_RECV]), &size.s_recv[2]);
      pos =
        cps_fmt (pos,
                 lb_sdiv (stat->rec[CPS_REC_SEND_TIME],
                          stat->rec[CPS_REC_SEND]), &size.s_send[2]);
    }

  *pos++ = '|';
  *pos = 0;

  out ("%s", buf);

  for (i = 0; i < CPS_CNT_NUM; ++i)
    {
      if (stat->cnt[i])
        {
          if (cnt_num++ == 0)
            out (" { %s:%s", cps_stat_name[i], f_uint (stat->cnt[i]));
          else
            out (" %s:%s", cps_stat_name[i], f_uint (stat->cnt[i]));
        }
    }

  if (cnt_num)
    out (" }\n");
  else
    out ("\n");

  for (i = 1; i < CPS_ERR_NUM; ++i)
    {
      if (stat->err[i])
        out ("<E%d:%s> %s\n", i, f_uint (stat->err[i]), strerror (i));
    }
  if (stat->err[0])
    out ("<E-:%s> Other error\n", f_uint (stat->err[0]));
}

void
cps_close ()
{
  cps.run_state = CPS_CLOSING;
}

void
cps_timer (uint64_t nsec)
{
  const static struct timespec delay = {.tv_sec = 0,.tv_nsec =
      CPS_DELAY_MS * 1000 * 1000
  };

  int i, j;
  struct cps_stat sum = { 0 };
  struct cps_stat *curr = cps.curr;

  cps.curr = cps.next;
  cps.next = curr;

  /*wait for cps.curr use */
  (void) nanosleep (&delay, NULL);

  for (i = 0; i < cps.thread_num; ++i, ++curr)
    {
      struct cps_thread *thread = cps.thread[i];

      curr->cnt[CPS_CNT_CONN_NUM] = thread->conn_num;
      if (cps.verbose)
        cps_output (thread->index, curr, nsec);

      for (j = 0; j < CPS_REC_NUM; ++j)
        {
          sum.rec[j] += curr->rec[j];
          curr->rec[j] = 0;
        }

      for (j = 0; j < CPS_CNT_NUM; ++j)
        {
          sum.cnt[j] += curr->cnt[j];
          curr->cnt[j] = 0;
        }

      for (j = 0; j < CPS_ERR_NUM; ++j)
        {
          sum.err[j] += curr->err[j];
          curr->err[j] = 0;
        }
    }

  cps_output (-1, &sum, nsec);
}

int
cps_loop ()
{
  const static struct timespec timeout = {.tv_sec = 0,.tv_nsec =
      CPS_TIMER_MS * 1000 * 1000
  };

  struct timespec begin, from;
  time_t next_time = cps.interval;

  LB_TIME (begin);
  from = begin;

  while (cps.run_state == CPS_RUNNING)
    {
      struct timespec now;

      (void) nanosleep (&timeout, NULL);

      LB_TIME (now);

      if (cps.client)
        {
          if (LB_CMP_S (now, begin, cps.test_time))
            cps_close ();
        }

      if (!LB_CMP_S (now, begin, next_time))
        continue;

      cps_timer (LB_SUB_NS (now, from));

      from = now;
      next_time += cps.interval;
    }

  while (cps.run_state == CPS_CLOSING && cps.active_thread)
    {
      (void) nanosleep (&timeout, NULL);
    }

  return 0;
}

int
cps_start ()
{
  int i;
  void *(*proc) (void *);
  const char *name;

  cps.conn =
    (struct cps_conn *) malloc (sizeof (struct cps_conn) * CPS_MAX_FD);
  ERR_RETURN (!cps.conn, -1, "Out of memory\n");

  if (cps.thread_num <= 0)
    {
      struct cps_thread *thread = cps_new_thread ();
      ERR_RETURN (!thread, -1, "Out of memory\n");

      cps.server_num = 1;
      thread->server_num = 1;
      thread->s_addr[0].sin_family = AF_INET;
      thread->s_addr[0].sin_port = htons (CPS_PORT_DEF);
      if (cps.client)
        {
          cps.client_num = 1;
          thread->client_num = 1;
          thread->c_addr_num = 1;
          thread->s_addr[0].sin_addr.s_addr = htonl (0x7F000001);
        }
      else
        {
          thread->s_addr[0].sin_addr.s_addr = INADDR_ANY;
        }
    }
  else if (cps.client)
    {
      for (i = 0; i < cps.thread_num; ++i)
        {
          if (cps.thread[i]->client_num)
            continue;
          cps.thread[i]->client_num = 1;
          cps.thread[i]->c_addr[0].ip = INADDR_ANY;
          cps.thread[i]->c_addr[0].ip_num = 1;
          cps.client_num++;
        }
    }

  if (cps.req_len <= 0)
    cps.req_len = CPS_REQ_DEF;
  if (cps.res_len <= 0)
    cps.res_len = CPS_RES_DEF;
  if (cps.evnum <= 0)
    cps.evnum = CPS_EVNUM_DEF;
  if (cps.interval <= 0)
    cps.interval = CPS_INTERVAL_DEF;
  if (cps.test_time <= 0)
    cps.test_time = CPS_TIME_DEF;
  if (cps.rate == 0)
    cps.rate = CPS_RATE_DEF;

  cps.curr = cps.records[0];
  cps.next = cps.records[1];

  if (cps.client)
    {
      proc = cps_c_thread;
      name = "client";
    }
  else
    {
      proc = cps_s_thread;
      name = "server";
    }

  cps_title ();

  for (i = 0; i < cps.thread_num; ++i)
    {
      if (cps.thread[i]->rate == 0)
        cps.thread[i]->rate = cps.rate;

      cps.thread[i]->epfd = _epoll_create (CPS_EPSIZE);
      ERR_RETURN (cps.thread[i]->epfd < 0, -1, "epoll_create(%d)=%d:%d\n",
                  CPS_EPSIZE, cps.thread[i]->epfd, errno);

      cps.thread[i]->tid =
        lb_thread (proc, cps.thread[i], "cps-%s-%d", name, i);
      ERR_RETURN (cps.thread[i]->tid == 0, -1, "Create thread %s-%d failed",
                  name, i);

      if (cps.thread[i]->core >= 0)
        {
          int ret = lb_setcpu (cps.thread[i]->tid, cps.thread[i]->core);
          WRN (ret != 0, "Bind core error thread:%d\n", i);
        }

      __sync_fetch_and_add (&cps.active_thread, 1);
    }

  cps.run_state = CPS_RUNNING;
  futex_wake (&cps.run_state, cps.thread_num);

  return 0;
}

void
cps_exit ()
{
  int i;

  cps.run_state = CPS_EXIT;

  for (i = 0; i < cps.thread_num; ++i)
    {
      int fd;
      struct cps_thread *thread = cps.thread[i];

      if (!thread)
        continue;

      if (thread->tid)
        pthread_join (thread->tid, NULL);

      if (thread->epfd >= 0)
        _close (thread->epfd);

      for (fd = thread->server; fd >= 0; fd = CPS_CONN (fd)->next)
        _close (fd);

      for (fd = thread->conn; fd >= 0; fd = CPS_CONN (fd)->next)
        _close (fd);

      cps.thread[i] = NULL;
      free (thread);
    }

  if (cps.conn)
    free (cps.conn);
}

void
cps_break (int s)
{
  DBG (" SIGNALED %d running:%d\n", s, cps.run_state);
  out ("\n");

  if (cps.run_state == CPS_INIT || cps.run_state == CPS_RUNNING)
    cps_close ();
  else if (cps.run_state != CPS_EXIT)
    cps_exit ();
  else
    exit (1);
}

void
cps_sigpipe (int s)
{
  DBG ("SIGPIPE\n");
}

int
cps_init ()
{
  struct sigaction s = { 0 };

  (void) sigemptyset (&s.sa_mask);

  s.sa_flags = SA_NODEFER;
  s.sa_handler = (void *) cps_break;
  (void) sigaction (SIGINT, &s, NULL);
  (void) sigaction (SIGQUIT, &s, NULL);

  s.sa_handler = cps_sigpipe;
  (void) sigaction (SIGPIPE, &s, NULL);

//    lb_sigsegv_setup();

  cps.CPU_NUM = get_nprocs ();

  if (cps.CPU_NUM <= 0)
    cps.CPU_NUM = 1;

  return 0;
}

#ifndef EXEC_CPS_C_
#define EXEC_CPS_C_

#define CPS_OPTIONS "d:e:T:t:r:ci:" DBGOPT "mvh"

static const struct option cps_options[] = {
  {"data", 1, 0, 'd'},
  {"interval", 1, 0, 'i'},
  {"evnum", 1, 0, 'e'},
  {"client", 0, 0, 'c'},
  {"thread", 1, 0, 't'},
  {"rate", 1, 0, 'r'},
  {"time", 1, 0, 'T'},
  DBGOPT_LONG {"more", 0, 0, 'm'},
  {"verbose", 0, 0, 'v'},
  {"help", 0, 0, 'h'},
  {0, 0, 0, 0}
};

enum
{
  CPSOPT_SERVER = 0,
  CPSOPT_S,
  CPSOPT_CLIENT,
  CPSOPT_C,
  CPSOPT_RATE,
  CPSOPT_CORE,
  CPSOPT_CF,
  CPSOPT_SF,
};

char *const cps_tokens[] = {
  [CPSOPT_SERVER] = "server",
  [CPSOPT_S] = "s",
  [CPSOPT_CLIENT] = "client",
  [CPSOPT_C] = "c",
  [CPSOPT_RATE] = "rate",
  [CPSOPT_CORE] = "core",
  [CPSOPT_CF] = "cf",
  [CPSOPT_SF] = "sf",
  NULL
};

void
cps_usage (const char *name)
{
  out ("USAGE: %s [OPTIONS] [SERVER-ADDRESS]	# %s version\n", name,
       VERSION_NAME);
  out (" Options:\n");
  out
    ("  -i, --interval=#				report time(default: %ds max:%ds)\n",
     CPS_INTERVAL_DEF, CPS_INTERVAL_MAX);
  out
    ("  -c, --client 				server address list for one thread\n");
  out
    ("  -e, --evnum 					epoll event number(default:%d max:%d)\n",
     CPS_EVNUM_DEF, CPS_EVNUM_MAX);
  out
    ("  -T, --time=# 			 C 	test time(default: %ds max:%ds)\n",
     CPS_TIME_DEF, CPS_TIME_MAX);
  out
    ("  -d, --data=#[:#] 		 C  request and response data length(default:%d:%d max:%d)\n",
     CPS_REQ_DEF, CPS_RES_DEF, CPS_DATA_MAX);
  out
    ("  -r, --rate=#[k|m|w] 		 C  global connect rate per each thread(CPS, default: %d max:%d)\n",
     CPS_RATE_DEF, CPS_RATE_MAX);
  out
    ("  -t, --thread=CONFIG 			  set one net and thread(max: %d)\n",
     CPS_THREAD_MAX);
  out
    ("	  server=X.X.X.X:P 			  server address set(max: %d)\n",
     CPS_SERVER_MAX);
  out
    (" 	  core=# 					  bind to core\n");
  out
    (" 	  client=X.X.X.X 		 C 	  client ip address set(max: %d max ip: %d)\n",
     CPS_CLIENT_IAS_MAX, CPS_CLIENT_MAX);
  out
    ("	  rate=# 				 C 	  set connect rate for this thread(default: use global set)\n");
  out
    ("	  cf 					 C 	  client loop first(default: both)\n");
  out
    ("	  sf 					 C 	  server loop first(default: both)\n");
#ifdef DEBUG
  out
    ("  -D, --debug 					show debug information\n");
#endif
  out
    ("  -m, --more 					show more statistics\n");
  out
    ("  -v, --verbose 				show thread statistics\n");
  out ("  -h, --help					help\n");
  out (" IMPORTANT:\n");
  out
    ("  socket()			EMFILE(%d) error: ulimit -n 1048576\n",
     EMFILE);
  out
    ("  bind()		EADDRINUSE(%d) error: echo 1 > /proc/sys/net/ipv4/tcp_tw_recycle\n",
     EADDRINUSE);
  out
    ("  connect() EADDRNOTAVAIL(%d) error: echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse\n",
     EADDRNOTAVAIL);
  out
    (" 									  echo \"3000 65534\" > /proc/sys/net/ipv4/ip_local_port_range\n");
}

inline static uint64_t
cps_p_rate (const char *arg)
{
  uint64_t rate = p_uint (arg, CPS_RATE_MAX, &arg);

  if (!arg)
    return (uint64_t) - 1ul;

  switch (*arg)
    {
    case 'm':                  /* fall through */
    case 'M':
      rate *= 100;              /* fall through */
    case 'w':                  /* fall through */
    case 'W':
      rate *= 10;               /* fall through */
    case 'k':                  /* fall through */
    case 'K':
      rate *= 1000;
      arg++;
      break;
    }

  if (*arg)
    return (uint64_t) - 1ul;

  return rate;
}

int
cps_opts (char *opts)
{
  struct cps_thread *thread;
  struct inaddrs *client;
  struct sockaddr_in *server;

  ERR_RETURN (cps.thread_num >= CPS_THREAD_MAX, -1,
              "Too many thread, max %d\n", CPS_THREAD_MAX);

  thread = cps_new_thread ();
  ERR_RETURN (!thread, -1, "Out of memory\n");
  server = thread->s_addr;
  client = thread->c_addr;

  while (*opts)
    {
      char *value;
      const char *end;
      int ret = getsubopt (&opts, cps_tokens, &value);
      switch (ret)
        {
        case CPSOPT_SERVER:
        case CPSOPT_S:
          {
            int i;
            uint64_t num;
            struct inaddrs addr;

            end = p_addr_set (value, &addr, PA_DEF_PORT | CPS_PORT_DEF);
            ERR_RETURN (!end
                        || *end, -1, "Invalid server address '%s'.\n", value);

            num = (uint64_t) addr.ip_num * addr.port_num;
            ERR_RETURN (num > CPS_SERVER_MAX - thread->server_num, -1,
                        "Too many server, max %d\n", CPS_SERVER_MAX);

            for (i = 0; i < addr.ip_num; ++i)
              {
                uint32_t ip = addr.ip + i;
                uint16_t j;
                for (j = 0; j < addr.port_num; ++j)
                  {
                    server->sin_family = AF_INET;
                    server->sin_addr.s_addr = htonl (ip);
                    server->sin_port = htons (addr.port + j);
                    server++;
                  }
              }
            thread->server_num += num;
            break;
          }
        case CPSOPT_CLIENT:
        case CPSOPT_C:
          {
            ERR_RETURN (thread->c_addr_num >= CPS_CLIENT_IAS_MAX, -1,
                        "Too many client set, max %d\n", CPS_CLIENT_IAS_MAX);

            end = p_addr_set (value, client, PA_NO_PORT);
            ERR_RETURN (!end
                        || *end, -1, "Invalid client address '%s'.\n", value);
            ERR_RETURN (client->ip_num > CPS_CLIENT_MAX - thread->client_num,
                        -1, "Too many client, max %d\n", CPS_CLIENT_MAX);

            client->port = 0;
            client->port_num = 1;
            thread->c_addr_num++;
            thread->client_num += client->ip_num;
            client++;
            break;
          }
        case CPSOPT_RATE:
          thread->rate = cps_p_rate (value);
          ERR_RETURN (thread->rate > CPS_RATE_MAX, -1,
                      "Invalid thread rate '%s'\n", value);
          break;

        case CPSOPT_CF:
          thread->loop = CPS_LOOP_CF;
          break;
        case CPSOPT_SF:
          thread->loop = CPS_LOOP_SF;
          break;

        case CPSOPT_CORE:
          thread->core = (int) p_int (value, cps.CPU_NUM - 1, &end);
          ERR_RETURN (!end || *end
                      || thread->core <= 0, -1, "Invalid bind core '%s'.\n",
                      value);
          break;

        default:
          ERR_RETURN (1, -1, "Unknown thread option '%s'\n", value);
        }
    }

  ERR_RETURN (!thread->server_num, -1, "No server set for net %d\n",
              thread->index);

  cps.server_num += thread->server_num;
  cps.client_num += thread->client_num;
  return 0;
}

int
cps_args (int argc, char *argv[])
{
  int opt, index;

  while (EOF !=
         (opt = getopt_long (argc, argv, CPS_OPTIONS, cps_options, &index)))
    {
      const char *end;

      switch (opt)
        {
        case 't':
          if (cps_opts (optarg))
            return -1;
          break;

        case 'c':
          cps.client = 1;
          break;

        case 'd':
          cps.req_len = (int) p_int (optarg, CPS_DATA_MAX, &end);
          ERR_RETURN (!end, -1, "Invalid data length '%s'\n", optarg);
          if (*end == ':')
            {
              end++;
              cps.res_len = (int) p_int (end, CPS_DATA_MAX, &end);
              ERR_RETURN (!end, -1, "Invalid response data length '%s'\n",
                          optarg);
            }
          else
            {
              cps.res_len = cps.req_len;
            }
          ERR_RETURN (*end != 0, -1, "Invalid data length '%s'\n", optarg);
          break;

        case 'i':
          cps.interval = (int) p_int (optarg, CPS_INTERVAL_MAX, &end);
          ERR_RETURN (!end || *end, -1, "Invalid interval '%s'\n", optarg);
          break;
        case 'e':
          cps.evnum = (int) p_int (optarg, CPS_EVNUM_MAX, &end);
          ERR_RETURN (!end
                      || *end, -1, "Invalid event number '%s'\n", optarg);
          break;
        case 'T':
          cps.test_time = (int) p_int (optarg, CPS_TIME_MAX, &end);
          ERR_RETURN (!end || *end, -1, "Invalid test time '%s'\n", optarg);
          break;
        case 'r':
          cps.rate = cps_p_rate (optarg);
          ERR_RETURN (cps.rate > CPS_RATE_MAX, -1, "Invalid rate '%s'\n",
                      optarg);
          break;
        case 'v':
          cps.verbose = 1;
          break;
        case 'm':
          cps.more = 1;
          break;

#ifdef DEBUG
        case 'D':
          enable_debug = 1;
          break;
#endif
        case 'h':
          cps_usage (argv[0]);
          exit (0);
        case '?':
          err ("Invalid arguments\n");
          return -1;
        default:
          err ("Unknown option '%c'.\n", opt);
          return -1;
        }
    }

  return 0;
}

#endif /* #ifndef EXEC_CPS_C_ */

int
main (int argc, char *argv[])
{
  int ret;

  if (cps_init ())
    return 1;

  cps_args (argc, argv) || cps_start () || cps_loop ();

  cps_exit ();
  return 0;
}
