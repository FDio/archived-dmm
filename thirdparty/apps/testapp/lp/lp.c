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

void lp_exec (struct lp_worker *worker);

#define LP_OPTIONS "s:c:bi:e:m:nwEC" DBGOPT "vh"

static const struct option lp_options[] = {
  {"block", 0, 0, 'b'},
  {"server", 1, 0, 's'},
  {"client", 1, 0, 'c'},
  {"nodelay", 0, 0, 'n'},
  {"interval", 1, 0, 'i'},
  {"no-error", 1, 0, 'e'},
  {"error-msg", 0, 0, 'E'},
  {"core", 1, 0, 'm'},
  DBGOPT_LONG {"watch", 0, 0, 'w'},
  {"no-color", 0, 0, 'C'},
  {"verbose", 0, 0, 'v'},
  {"help", 0, 0, 'h'},
  {0, 0, 0, 0}
};

static const char *MODES[] = {
  [LP_RAND] = "*random link",
  [LP_SYNC] = "=sync increment",
  [LP_CPS] = "}client per server",
  [LP_SPC] = "{server per client",
};

struct lp_var lp = { 0 };

void
lp_dump_sess (int fd)
{
  char buf[256];
  struct lp_sess *sess = LP_SESS (fd);

  co_init (buf, sizeof (buf));

  co_append (buf, 80,
             "fd:%d sess:%p state:0x%x test:%u epout:%u io_num:%u query:%d reply:%d\n",
             fd, sess, sess->state, sess->test, sess->epout, sess->io_num,
             sess->query, sess->reply);
  co_append (buf, 50, " nest-sess:%d prev-sess:%p", sess->next_sess,
             sess->prev_sess);
  co_app_if (sess->prev_sess, buf, 10, "(%ld)",
             CON_OF (sess->prev_sess, struct lp_sess, next_sess) - lp.sess);
  co_append (buf, 50, " nest-rest:%d prev-rest:%p", sess->next_rest,
             sess->prev_rest);
  co_app_if (sess->prev_rest, buf, 10, "(%ld)",
             CON_OF (sess->prev_rest, struct lp_sess, next_rest) - lp.sess);
  co_append (buf, 30, " time:%ld.%09ld\n", sess->time.tv_sec,
             sess->time.tv_nsec);

  co_flush (buf);
}

void
lp_clean (struct lp_worker *worker)
{
  int i, fd;

  while (lp.run_state == LP_CLEAN)
    {
      fd = worker->conn.first;
      if (fd < 0)
        break;
      lp_del_conn (worker, fd, LP_SESS (fd));
    }
  LP_ASSERT (worker->conn.num == 0);
  LP_ASSERT (worker->conn.first == -1);
  LP_ASSERT (worker->conn.last = &worker->conn.first);

  while (lp.run_state == LP_CLEAN)
    {
      fd = worker->sess.first;
      if (fd < 0)
        break;
      lp_del_sess (worker, fd);
    }
  LP_ASSERT (worker->sess.num == 0);
  LP_ASSERT (worker->sess.first == -1);
  LP_ASSERT (worker->sess.last = &worker->sess.first);

  for (i = 0; i < LP_MAX_TEST; ++i)
    {
      LP_ASSERT (worker->rest[i].num == 0);
      LP_ASSERT (worker->rest[i].first == -1);
      LP_ASSERT (worker->rest[i].last = &worker->rest[i].first);
      LP_ASSERT (worker->wait[i].num == 0);
      LP_ASSERT (worker->wait[i].first == -1);
      LP_ASSERT (worker->wait[i].last = &worker->rest[i].first);
    }
}

void *
lp_thread (void *arg)
{
  const uint64_t one = 1;
  struct lp_worker *worker = (struct lp_worker *) arg;

  (void) __sync_or_and_fetch (&lp.active_worker, one << worker->index);

  futex_wait (&lp.run_state, LP_INIT);

  if (lp.client_mode)
    lp_client (worker);
  else
    lp_server (worker);

  lp_clean (worker);

  out ("%s! worker %d return%s\n", CR, worker->index, CC);
  (void) __sync_and_and_fetch (&lp.active_worker, ~(one << worker->index));

  return NULL;
}

void
lp_round (int id)
{
  struct lp_test *test = &lp.test[id];
  char buf[128];

  co_init (buf, sizeof (buf));

  co_append (buf, 30, "%s! round %d:", CR, id);
  co_append (buf, 30, " target:%s",
             test->target == LP_TARGET_INF ? "*" : f_uint (test->target));
  co_append (buf, 30, " time:%s",
             test->time == LP_TIME_INF ? "*" : f_uint (test->time));
  co_append (buf, 30, " up:%s",
             test->up == LP_UP_INF ? "*" : f_uint (test->up));
  co_append (buf, 30, " down:%s",
             test->down == LP_DOWN_INF ? "*" : f_uint (test->down));
  co_append (buf, 30, " query:%u", test->query);
  co_append (buf, 30, " reply:%u", test->reply);
  co_append (buf, 30, " times:%s",
             test->times == LP_TIMES_INF ? "*" : f_uint (test->times));
  co_app_if (test->close_after_io, buf, 1, "-");
  co_append (buf, 30, " period:%u", test->period);
  co_append (buf, 30, " wait:%u", test->wait);
  co_append (buf, 30, " %s\n", CC);

  co_flush (buf);
}

int
lp_start ()
{
  int i;
  cpu_set_t set;

  lp.sess = (struct lp_sess *) calloc (LP_MAX_FD, sizeof (struct lp_sess));
  ERR_RETURN (!lp.sess, -1, "Out of memory\n");

  lp.run_state = LP_INIT;

  lp.curr = lp.stat[0];
  lp.next = lp.stat[1];

  if (lp.interval == 0)
    lp.interval = LP_INTERVAL_DEF;

  if (lp.core)
    {
      CPU_ZERO (&set);
      for (i = 0; i < 64; ++i)
        {
          if (lp.core & (1 << i))
            CPU_SET (i, &set);
        }
    }

  for (i = 0; i < lp.worker_num; ++i)
    {
      int ret;
      struct epoll_event event;
      struct lp_worker *worker = LP_WORKER (i);

      out ("[%d] creating worker\n", i);

      worker->io_buf = malloc (LP_IOBUF_SIZE);
      ERR_RETURN (!worker->io_buf, -1, "Out of memory for IO buffer\n");

      worker->ev_buf = malloc (sizeof (struct epoll_event) * LP_EVENT_NUM);
      ERR_RETURN (!worker->ev_buf, -1, "Out of memory for events buffer\n");

      TP (epoll_create);
      worker->epfd = _epoll_create (10);
      ERR_RETURN (worker->epfd < 0, -1, "epoll_create()=%d:%d\n",
                  worker->epfd, errno);
      worker->ctlfd = eventfd (0, 0);
      ERR_RETURN (worker->ctlfd < 0, -1, "eventfd()=%d:%d\n", worker->epfd,
                  errno);
      TQ (epoll_create);

      event.events = EPOLLIN;
      event.data.u64 = LP_EV_MK (LP_CONTROL_TYPE, worker->ctlfd);
      ret = _epoll_ctl (worker->epfd, EPOLL_CTL_ADD, worker->ctlfd, &event);
      ERR_RETURN (ret, -1, "epoll_ctl(epfd:%d, add, evfd:%d,)=%d:%d\n",
                  worker->epfd, worker->ctlfd, ret, errno);

      worker->tid =
        lb_thread (lp_thread, worker, "lp-%s-%d",
                   lp.client_mode ? "client" : "server", i);
      ERR_RETURN (worker->tid <= 0, -1, "Create worker thread failed\n");

      if (lp.core)
        {
          ret = pthread_setaffinity_np (worker->tid, sizeof (set), &set);
          if (ret)
            err ("Bind core failed!\n");
        }

      if (lp.client_mode)
        {
          size_t size;

          size =
            sizeof (struct lb_run) + sizeof (struct lb_slot) * LP_UP_SLOT;
          worker->up_run = (struct lb_run *) calloc (1, size);
          ERR_RETURN (!worker->up_run, -1, "Out of memory for up run\n");

          size =
            sizeof (struct lb_run) + sizeof (struct lb_slot) * LP_DOWN_SLOT;
          worker->down_run = (struct lb_run *) calloc (1, size);
          ERR_RETURN (!worker->down_run, -1, "Out of memory for down run\n");

          out
            ("[%d] worker %ld created, client:%d server:%d epfd:%d ctlfd:%d\n",
             worker->index, pthread_self (), worker->client_num,
             worker->server_num, worker->epfd, worker->ctlfd);
        }
      else
        {
          int j;
          TP (lp_listen);
          for (j = 0; j < worker->server_num; ++j)
            {
              if (lp_listen (worker, j))
                return -1;
            }
          TQ (lp_listen);
          out ("[%d] worker %ld created, server:%d epfd:%d ctlfd:%d\n",
               worker->index, pthread_self (), worker->server_num,
               worker->epfd, worker->ctlfd);
        }
    }

  out ("%s! running %s\n", CR, CC);
  if (lp.client_mode)
    {
      lp_round (0);
    }

  lp.run_state = LP_EXEC;

  futex_wake (&lp.run_state, lp.worker_num);
  return 0;
}

void
lp_stop (int state)
{
  int i;

  lp.run_state = state;

  for (i = 0; i < lp.worker_num; ++i)
    {
      struct lp_worker *worker = LP_WORKER (i);
      if (worker->tid && worker->ctlfd >= 0)
        {
          (void) lp_post_cmd (worker->ctlfd, LP_CMD_STOP);
        }
    }
}

#define _FREE(p) do { if (p) { free(p); p = NULL; } } while (0)

void
lp_exit ()
{
  int i;

  lp_stop (LP_EXIT);

  for (i = 0; i < lp.worker_num; ++i)
    {
      int fd;
      struct lp_worker *worker = LP_WORKER (i);

      if (worker->tid)
        {
        const struct timespec wait = { tv_sec: 3, tv_nsec:0 };
          (void) pthread_timedjoin_np (worker->tid, NULL, &wait);
          worker->tid = 0;
        }

      for (fd = worker->server.first; fd >= 0; fd = LP_SESS (fd)->next_sess)
        _close (fd);

      lp_clean (worker);

      if (worker->ctlfd >= 0)
        {
          _close (worker->ctlfd);
          worker->ctlfd = -1;
        }
      if (worker->epfd >= 0)
        {
          _close (worker->epfd);
          worker->epfd = -1;
        }

      _FREE (worker->server_addr);
      _FREE (worker->client_addr);
      _FREE (worker->up_run);
      _FREE (worker->down_run);
      _FREE (worker->io_buf);
      _FREE (worker->ev_buf);
    }

  _FREE (lp.sess);
}

inline static const char *
lp_errmsg (int e)
{
  static const char *errmsg[LP_ERRNO_NUM] = { 0 };
  if (NULL == errmsg[e])
    errmsg[e] = strerror (e);
  return errmsg[e];
}

const static char *lp_cntmsg[LP_CNT_NUM] = {
  [LP_E_SOCKET] = "socket",
  [LP_E_BIND] = "bind",
  [LP_E_ACCEPT] = "accept",
  [LP_E_CONNECT] = "connect",
  [LP_E_NODELAY] = "nodelay",
  [LP_E_NONBLOCK] = "nonblock",
  [LP_E_REUSEADDR] = "reuseaddr",
  [LP_E_REUSEPORT] = "reuseport",
  [LP_E_RECV] = "recv",
  [LP_E_SEND] = "send",

  [LP_E_EPADD] = "ep-add",
  [LP_E_EPMOD] = "ep-mod",
  [LP_E_EPDEL] = "ep-del",
  [LP_E_EPWAIT] = "ep-wait",
  [LP_E_EPUNUSED] = "ep-unused",
  [LP_E_EPHUP] = "ep-hup",
  [LP_E_EPERR] = "ep-err",
  [LP_E_EPINOUT] = "ep-inout",
  [LP_E_EVIDLE] = "ep-idle",
  [LP_E_EPEVENT] = "ep-event",

  [LP_E_IOSHUT] = "io-shut",
  [LP_E_IOSIZE] = "io-size",
  [LP_E_IOMORE] = "io-more",
  [LP_E_IOEXCEED] = "io-exceed",
  [LP_E_IOSEND0] = "io-send0",

  [LP_W_CREATE] = "cre",
  [LP_W_SOCKET] = "soc",
  [LP_W_BIND] = "bin",
  [LP_W_CONNECT] = "con",
  [LP_W_CONNECTED] = "est",
  [LP_W_ACCEPT] = "acc",
  [LP_W_CLOSE] = "clo",
};

void
lp_output (char buf[], const struct lp_stat *stat, uint64_t nsec, int mask)
{
  int i;
  const uint64_t *cnt = stat->cnt;
  static int w_num = 0, w_up = 0, w_down = 0, w_conn = 0;
  static int w_q_mb = 0, w_q_cp = 0, w_r_mb = 0, w_r_cp = 0;

  co_append (buf, 5, " %s ", CH);
  w_num = co_wr_uint (buf, cnt[LP_REC_NUM], w_num);
  co_append (buf, 5, "%s", CC);

  co_append (buf, 3, " < ");
  w_up = co_wr_uint (buf, lb_gdiv (cnt[LP_CONNECTED], nsec), w_up);
  if (lp.client_mode && !lp.block_connecting)
    {
      co_append (buf, 1, " / ");
      w_conn = co_wr_uint (buf, lb_gdiv (cnt[LP_CONNECT], nsec), w_conn);
    }
  co_append (buf, 3, " - ");
  w_down = co_wr_uint (buf, lb_gdiv (cnt[LP_CLOSE], nsec), w_down);
  co_append (buf, 3, " > ");

  co_append (buf, 3, " [ ");
  w_q_mb =
    co_wr_uint (buf,
                lb_gdiv (cnt[LP_QUERY_BYTE] * 8, nsec /* * (1000000 / 8) */ ),
                w_q_mb);
  co_append (buf, 1, " ");
  w_q_cp = co_wr_uint (buf, lb_gdiv (cnt[LP_QUERY_COMP], nsec /* * 1000 */ ),
                       w_q_cp);
  co_append (buf, 3, " : ");
  w_r_mb =
    co_wr_uint (buf,
                lb_gdiv (cnt[LP_REPLY_BYTE] * 8, nsec /* * (1000000 / 8) */ ),
                w_r_mb);
  co_append (buf, 1, " ");
  w_r_cp = co_wr_uint (buf, lb_gdiv (cnt[LP_REPLY_COMP], nsec /* * 1000 */ ),
                       w_r_cp);
  co_append (buf, 3, " ] ");

  co_app_if (cnt[LP_FAILED], buf, 40, " F:%s%s%s",
             FR__, f_uint (lb_gdiv (cnt[LP_FAILED], nsec)), CC);

  if (mask & LP_W_SIGN)
    {
      co_append (buf, 8, "  time{");
      for (i = LP_W_BEGIN; i < LP_W_END; i += 2)
        co_app_if (cnt[i], buf, 60, " %s:%s", lp_cntmsg[i],
                   f_uint (cnt[i + 1] / cnt[i]));
      co_append (buf, 4, " }");
    }

  if (mask & LP_E_SIGN)
    {
      co_append (buf, 8, "  err{");
      for (i = LP_E_BEGIN; i < LP_E_END; ++i)
        co_app_if (cnt[i], buf, 60, " %s:%s", lp_cntmsg[i], f_uint (cnt[i]));
      co_append (buf, 4, " }");
    }

  if (!lp.err_msg && (mask & LP_ERR_SIGN))
    {
      co_append (buf, 5, "  E:{");
      for (i = 1; i < LP_ERRNO_NUM; ++i)
        co_app_if (stat->err[i], buf, 40, " %d:%lu", i, stat->err[i]);
      co_app_if (stat->err[0], buf, 30, " -:%lu", stat->err[0]);
      co_append (buf, 5, " }");
    }

  co_append (buf, 4, "\n");

  if (lp.err_msg && (mask & LP_ERR_SIGN))
    {
      for (i = 1; i < LP_ERRNO_NUM; ++i)
        co_app_if (stat->err[i], buf, 100, "<E%d:%lu> %s\n", i, stat->err[i],
                   lp_errmsg (i));
      co_app_if (stat->err[0], buf, 100, "<E-:%s> Other error\n",
                 f_uint (stat->err[0]));
    }
}

void
lp_timer (uint64_t nsec)
{
  const static struct timespec delay = {.tv_sec = 0,.tv_nsec =
      LP_DELAY_MS * 1000 * 1000
  };
  static int line = -2;
  static int base;

  int i, second, total = 0;
  char buf[256];
  struct tm *lc;
  struct lp_stat *curr, sum = { 0 };

  curr = lp.curr;
  lp.curr = lp.next;
  lp.next = curr;

  {
    time_t tv = time (NULL);
    lc = localtime (&tv);
  }

  co_init (buf, sizeof (buf));

  (void) nanosleep (&delay, NULL) /* wait for cps.curr use */ ;

  for (i = 0; i < lp.worker_num; ++i)
    {
      int j, mask = 0;
      uint64_t count = 0;

      curr->cnt[LP_REC_NUM] = LP_WORKER (i)->sess.num;

      for (count = 0, j = 0; j < LP_R_END; ++j)
        {
          sum.cnt[j] += curr->cnt[j];
          count += curr->cnt[j];
        }
      if (count)
        mask |= LP_R_SIGN;

      for (count = 0, j = LP_E_BEGIN; j < LP_E_END; ++j)
        {
          sum.cnt[j] += curr->cnt[j];
          count += curr->cnt[j];
        }
      if (count)
        mask |= LP_E_SIGN;

      if (lp.watch)
        {
          for (count = 0, j = LP_W_BEGIN; j < LP_W_END; j += 2)
            {
              sum.cnt[j] += curr->cnt[j];
              sum.cnt[j + 1] += curr->cnt[j + 1];
              count += curr->cnt[j];
            }
          if (count)
            mask |= LP_W_SIGN;
        }

      for (count = 0, j = 0; j < LP_ERRNO_NUM; ++j)
        {
          sum.err[j] += curr->err[j];
          count += curr->err[j];
        }
      if (count)
        mask |= LP_ERR_SIGN;

      if (mask && lp.verbose)
        {
          co_append (buf, 10, " %4dw ", i);
          lp_output (buf, curr + i, nsec, mask);
        }

      total |= mask;
    }

  if (total)
    {
      line = line < 0 ? 0 : line + 1;
      if (line == 0)
        {
          base = lc->tm_hour * 3600 + lc->tm_min * 60 + lc->tm_sec;
        }
    }
  else
    {
      line = line > 0 ? 0 : line - 1;
      if (line == -1)
        co_append (buf, 5, "\n");
    }

  if (line >= 0)
    {
      if (line)
        {
          second = (lc->tm_hour * 3600 + lc->tm_min * 60 + lc->tm_sec) - base;
          while (second < 0)
            second += (24 * 3600);
          co_append (buf, 10, " %5d", second);
        }
      else
        {
          co_append (buf, 10, " %2d:%02d ", lc->tm_hour, lc->tm_min);
        }
      lp_output (buf, &sum, nsec, total);
    }

  co_flush (buf);

  (void) memset (curr, 0, sizeof (struct lp_stat) * lp.worker_num);
}

int
lp_loop ()
{
  const static struct timespec timeout = {.tv_sec = 0,.tv_nsec = LP_LOOP_TIMER
  };

  struct timespec begin, from, last_begin;
  time_t next_time = lp.interval;

  LB_TIME (begin);
  from = begin;
  last_begin = begin;

  while (lp.run_state > 0)
    {
      struct timespec now;

      (void) nanosleep (&timeout, NULL);

      LB_TIME (now);

      if (lp.run_state == LP_CLEAN)
        {
          if (lp.active_worker == 0)
            break;
        }

      if (lp.client_mode && lp.run_state == LP_EXEC)
        {
          struct lp_test *test = &lp.test[lp.test_id];
          uint64_t total = lp_total_sess ();

          if (LB_CMP_S (now, last_begin, test->time)
              || (test->up >= test->down ? total >= test->target : total <=
                  test->target))
            {
              if (lp.test_id >= lp.test_num - 1)
                {
                  lp.run_state = LP_CLEAN;
                  out ("%s! cleanup%s\n", CR, CC);
                }
              else
                {
                  lp.test_id++; /* run changed */
                  last_begin = now;
                  lp_round (lp.test_id);
                }
            }
        }

      if (!LB_CMP_S (now, begin, next_time))
        continue;

      lp_timer (LB_SUB_NS (now, from));

      from = now;
      next_time += lp.interval;

      if (!lp.client_mode)
        {
          const struct timespec rest = {.tv_sec = lp.interval - 1,.tv_nsec =
              LP_LOOP_REST
          };
          (void) nanosleep (&rest, NULL);
        }
    }

  return 0;
}

#ifndef SIGNAL_LP_C_
#define SIGNAL_LP_C_

void
lp_break (int s)
{
  DBG (" SIGNALED %d running:%d\n", s, lp.run_state);
  out ("\n");

  if (lp.run_state == LP_CLEAN)
    {
      out ("%s! safe exit%s\n", CR, CC);
      lp_exit ();
    }
  else if (lp.run_state >= 0)
    {
      out ("%s! clean exit%s\n", CR, CC);
      lp_stop (LP_CLEAN);
    }
  else
    {
      out ("%s! direct exit%s\n", CR, CC);
      exit (1);
    }
}

void
lp_sigpipe (int s)
{
  DBG ("SIGPIPE\n");
}

int
lp_init ()
{
  struct sigaction s = { 0 };

  (void) sigemptyset (&s.sa_mask);

  s.sa_flags = SA_NODEFER;
  s.sa_handler = (void *) lp_break;
  (void) sigaction (SIGINT, &s, NULL);
  (void) sigaction (SIGQUIT, &s, NULL);

  s.sa_handler = lp_sigpipe;
  (void) sigaction (SIGPIPE, &s, NULL);

//        lb_sigsegv_setup();

  lp.CPU_NUM = get_nprocs ();
  if (lp.CPU_NUM <= 0)
    lp.CPU_NUM = 1;

  {
    struct timespec t;
    LB_TIME (t);
    srandom (getpid () + t.tv_sec + (t.tv_sec >> 32) + t.tv_nsec +
             (t.tv_nsec >> 32));
  }

  return 0;
}

#endif

void
lp_usage (const char *name)
{
  out ("USAGE: %s [OPTIONS] TEST-SET...	# %s version\n", name, VERSION_NAME);
}

void
lp_help (const char *name)
{
  lp_usage (name);
  out (" Options:\n");
  out ("  -s, --server LIST 		set one server address list\n");
  out ("			X.Y.Z.M-N:P1-P2,...\n");
  out ("  -c,  --client LIST 		set one client address list\n");
  out
    ("			CLIENT*SERVER: R.S.T.K-J:Pa-Pb,...*X.Y.Z.M-N:P1-P2,...\n");
  out ("			A,B,C,D*1,2		random link\n");
  out ("			A,B,C,D=1,2		A1B2C1D2\n");
  out ("			A,B,C,D}1,2		A1B1C1D1 A2B2C2D2\n");
  out
    ("			A,B,C,D{1,2		A1A2 B1B2 C1C2 D1D2\n");
  out
    ("  -b, --block 				  set block mode for connecting(client only)\n");
  out ("  -n, --nodelay 			  set nodelay\n");
  out ("  -i, --interval # 		  report time(default:%ds max:%ds)\n",
       LP_INTERVAL_DEF, LP_INTERVAL_MAX);
  out
    ("  -m, --core #HEX			  set bind cpu core mask(hex mode)\n");
#ifdef DEBUG
  out ("  -D, --debug 				  show debug information\n");
#endif
  out
    ("  -w, --watch 				  show watch time statistic\n");
  out ("  -e, --no-error #-#		  skip error\n");
  out ("  -E, --error-msg			  show error message\n");
  out ("  -C, --no-color			  no color\n");
  out ("  -v, --verbose			  show worker statistics\n");
  out ("  -h, --help 				  help\n");
  out (" TEST-SET for client\n");
  out
    ("	TARGET@TIME+UP-DOWN=QUERY:REPLY*TIMES-/PERIOD%%WAIT 		(client only)\n");
  out ("		TARGET 		max connection(default: INFINITE)\n");
  out (" 		@TIME 		max time(0 or default:INFINITE)\n");
  out
    (" 		+UP 		connect rate(default: 0 no connnect; *: INFINITE)\n");
  out
    (" 		-DOWN 		close rate(default: 0 no close; *: INFINITE)\n");
  out ("		=...		IO set(default: no IO)\n");
  out (" 		 QUERY 		send query data len(%u-%u)\n",
       LP_QUERY_MIN, LP_QUERY_MAX);
  out
    (" 		:REPLY 		receive response data len(0-%d; default: same with QUERY)\n",
     LP_REPLY_MAX);
  out
    (" 		*TIMES- 	IO times(0 or default: INFINITE; suffix-: IO then close)\n");
  out
    (" 		/PERIOD 	IO period time(0-%us; default: one by one)\n",
     LP_PERIOD_MAX);
  out
    (" 		%%WAIT 		 first IO wait time(0-%us; default: 0 no wait)\n",
     LP_WAIT_MAX);
  out (" UNITS:\n");
  out ("	k=1000 m=1000k g=1000m  w=10000  K=1024 M=1024K G=1024M\n");
  out (" 	s=Seconds m=Minutes h=Hours\n");
}

int
lp_args_test (const char *arg)
{
  const char *p;
  struct lp_test *test = &lp.test[lp.test_num];

  ERR_RETURN (lp.test_num >= LP_MAX_TEST, -1, "Too many test set, max:%d\n",
              LP_MAX_TEST);
  (void) memset (test, 0, sizeof (struct lp_test));

  if (*arg >= '0' && *arg <= '9')
    {
      test->target = p_value (arg, LP_TARGET_MAX, UB_1kmgwKMG, &p);
      ERR_RETURN (!p, -1, "Invalid test TARGET set: '%s'\n", arg);
    }
  else
    {
      test->target = LP_TARGET_DEF;
      p = arg;
    }

  if (*p == '@')
    {
      test->time = p_value (p + 1, LP_TIME_MAX, UB_hms1, &p);
      ERR_RETURN (!p, -1, "Invalid test TIME set: '%s'\n", arg);
    }
  else
    {
      test->time = LP_TIME_DEF;
    }

  if (*p == '+')
    {
      if (p[1] == '*')
        {
          test->up = LP_UP_INF;
          p += 2;
        }
      else
        {
          test->up = p_value (p + 1, LP_UP_MAX, UB_1kmgwKMG, &p);
          ERR_RETURN (!p, -1, "Invalid test UP-RATE set: '%s'\n", arg);
        }
    }
  else
    {
      test->up = LP_UP_DEF;
    }

  if (*p == '-')
    {
      if (p[1] == '*')
        {
          test->down = LP_DOWN_INF;
          p += 2;
        }
      else
        {
          test->down = p_value (p + 1, LP_DOWN_MAX, UB_1kmgwKMG, &p);
          ERR_RETURN (!p, -1, "Invalid test DOWN-RATE set: '%s'\n", arg);
        }
    }
  else
    {
      test->down = LP_DOWN_DEF;
    }

  if (*p == '=')
    {
      test->query = p_value (p + 1, LP_QUERY_MAX, UB_1kmgwKMG, &p);
      ERR_RETURN (!p
                  || test->query < LP_QUERY_MIN, -1,
                  "Invalid test QUERY '%s'\n", arg);

      if (*p == ':')
        {
          test->reply = p_value (p + 1, LP_REPLY_MAX, UB_1kmgwKMG, &p);
          ERR_RETURN (!p, -1, "Invalid test REPLY set: '%s'\n", arg);
        }
      else
        {
          test->reply = test->query;
        }

      if (*p == '*')
        {
          test->times = p_uint (p + 1, LP_TIMES_MAX, &p);
          ERR_RETURN (!p, -1, "Invalid test TIMES set: '%s'\n", arg);
          if (test->times == 0)
            test->times = LP_TIMES_INF;
          if (*p == '-')
            {
              test->close_after_io = 1;
              p++;
            }
        }
      else
        {
          test->times = LP_TIMES_DEF;
        }

      if (*p == '/')
        {
          test->period = p_value (p + 1, LP_PERIOD_MAX, UB_hms1, &p);
          ERR_RETURN (!p, -1, "Invalid test PRIOD set: '%s'\n", arg);
          if (*p == '%')
            {
              test->wait = p_value (p + 1, LP_WAIT_MAX, UB_hms1, &p);
              ERR_RETURN (!p, -1, "Invalid test WAIT set: '%s'\n", arg);
            }
          else
            {
              test->wait = LP_WAIT_DEF;
            }
        }
      else
        {
          test->period = LP_PERIOD_DEF;
          test->wait = 0;
        }
    }
  else
    {
      test->query = 0;
      test->reply = 0;
      test->times = 0;
      test->period = 0;
      test->wait = 0;
    }

  ERR_RETURN (*p, -1, "Invalid test set: '%s'\n", arg);

  if (test->up < test->down)
    test->down_mode = 1;
  lp.test_num++;
  return 0;
}

inline static void
lp_noerr (int b, int e)
{
  for (; b <= e; ++b)
    lp.no_err[b / 64] |= (1 << (b % 64));
}

/* -e M-N */
int
lp_args_noerr (const char *arg)
{
  int b, e;

  b = (int) p_uint (arg, LP_ERRNO_NUM, &arg);
  if (!arg)
    return -1;
  if (*arg == '-')
    {
      e = (int) p_uint (arg + 1, LP_ERRNO_NUM, &arg);
      if (!arg || e < b)
        return -1;
    }
  else
    {
      e = b;
    }

  if (*arg != 0)
    return -1;

  lp_noerr (b, e);

  return 0;
}

struct lp_worker *
lp_init_worker ()
{
  int i;
  struct lp_worker *worker = LP_WORKER (lp.worker_num);

  ERR_RETURN (lp.worker_num >= LP_MAX_WORKER, NULL,
              "Too many workers, limit:%d\n", LP_MAX_WORKER);

  (void) memset (worker, 0, sizeof (*worker));

  worker->index = lp.worker_num;
  worker->epfd = -1;
  worker->ctlfd = -1;

  lp_init_head (&worker->server);
  lp_init_head (&worker->sess);
  lp_init_head (&worker->conn);
  for (i = 0; i < LP_MAX_TEST; ++i)
    {
      lp_init_head (&worker->rest[i]);
      lp_init_head (&worker->wait[i]);
    }

  lp.worker_num++;

  return worker;
}

int
lp_args (int argc, char *argv[])
{
  int i, opt, index, ret;
  struct lp_worker *worker;
  const char *arg;
  int server_mode = 0;

  while (EOF !=
         (opt = getopt_long (argc, argv, LP_OPTIONS, lp_options, &index)))
    {
      const char *end;

      switch (opt)
        {
        case 'c':
          ERR_RETURN (server_mode, -1, "Only server or client\n");
          lp.client_mode = 1;
          worker = lp_init_worker ();
          if (!worker)
            return -1;
          worker->client_num = p_addrin_list (optarg, &worker->client_addr,
                                              LP_CLIENT_MAX,
                                              PA_DEF_PORT | PAL_NO_SPACE,
                                              &arg);
          ERR_RETURN (worker->client_num <= 0, -1,
                      "Bad client for address list '%s'\n", optarg);
          for (i = 0; i < CNT_OF (MODES); ++i)
            {
              if (*arg == MODES[i][0])
                break;
            }
          ERR_RETURN (i >= CNT_OF (MODES), -1,
                      "Bad mode for address list '%s'\n", optarg);
          worker->link_mode = i;
          arg++;
          worker->server_num = p_addrin_list (arg, &worker->server_addr,
                                              LP_SERVER_MAX,
                                              PA_MUST_PORT | PAL_NO_SPACE,
                                              NULL);
          ERR_RETURN (worker->server_num <= 0, -1,
                      "Bad server for address list '%s'\n", arg);
          break;
        case 's':
          ERR_RETURN (lp.client_mode, -1, "Only server or client\n");
          server_mode = 1;
          worker = lp_init_worker ();
          if (!worker)
            return -1;
          worker->server_num =
            p_addrin_list (optarg, &worker->server_addr, LP_SERVER_MAX,
                           PA_MUST_PORT | PAL_NO_SPACE, NULL);
          ERR_RETURN (worker->server_num <= 0, -1,
                      "Bad server for address list '%s'\n", optarg);
          break;

        case 'i':
          lp.interval = (int) p_int (optarg, LP_INTERVAL_MAX, &end);
          ERR_RETURN (!end || *end, -1, "Invalid interval '%s'\n", optarg);
          break;
        case 'e':
          ret = lp_args_noerr (optarg);
          ERR_RETURN (ret, ret, "Invalid no-error set '%s'\n", optarg);
          break;
        case 'm':
          lp.core = p_hex (optarg, &end);
          ERR_RETURN (!end
                      || lp.core >= (1 << lp.CPU_NUM), -1,
                      "Invalid bind core set\n");
          break;
        case 'C':
          lb_set_color (LB_NO_COLOR);
          break;

        case 'b':
          lp.block_connecting = 1;
          break;
        case 'n':
          lp.nodelay = 1;
          break;
        case 'w':
          lp.watch = 1;
          break;
        case 'E':
          lp.err_msg = 1;
          break;
        case 'v':
          lp.verbose = 1;
          break;

#ifdef DEBUG
        case 'D':
          enable_debug = 1;
          break;
#endif
        case 'h':
          lp_help (argv[0]);
          exit (0);
        case '?':
          err ("Invalid arguments\n");
          return -1;
        default:
          err ("Unknown option '%c'.\n", opt);
          return -1;
        }
    }

  ERR_RETURN (lp.worker_num <= 0, -1,
              "Please set server or client address\n");

  if (lp.client_mode)
    {
      for (index = optind; index < argc; ++index)
        {
          ret = lp_args_test (argv[index]);
          if (ret)
            return ret;
        }
      ERR_RETURN (lp.test_num <= 0, -1, "Please set test\n");
    }
  else
    {
      ERR_RETURN (optind < argc, -1, "Unknown option '%s'\n", argv[optind]);
    }

  return 0;
}

int
main (int argc, char *argv[])
{
  if (argc <= 1)
    {
      lp_usage (argv[0]);
      return 0;
    }

  if (lp_init ())
    return 1;

  if (lp_args (argc, argv) == 0 && lp_start () == 0)
    lp_loop ();

  lp_exit ();

  return 0;
}
