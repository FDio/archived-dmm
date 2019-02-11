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
#include "../bps/bps.h"

struct bps_var bps = { 0 };

/********************/

inline static int
bps_cpu ()
{
  int i;

  if (bps.bind_core == 0)
    return -1;

  for (i = 0; i < 64; ++i)
    {
      if (bps.bind_core & (1ul << i))
        {
          bps.bind_core &= ~(1ul << i);
          out ("mask:0x%lx cps:%d\n", bps.bind_core, i);
          return i;
        }
    }

  return -1;
}

void *
bps_send (void *arg)
{
  static char bps_send_buf[BPS_MAX_LEN];

  struct bps_sess *sess = (struct bps_sess *) arg;
  const int sid = BPS_SESS_ID (sess);
  int fd, sent = 0;
  char *buf = malloc (bps.msg_len);

  out ("client send\n");

  if (!buf)
    buf = bps_send_buf;

  futex_wait (&sess->fd, -1);
  __sync_synchronize ();

  fd = sess->fd;

  while (sess->state == BPS_RUNNING)
    {
      int ret = _send (fd, buf + sent, bps.msg_len - sent, 0);
      if (ret > 0)
        {
          sent += ret;
          bps.rec_now[sid].snd += ret;
          if (sent >= bps.msg_len)
            sent -= bps.msg_len;
        }
      else
        {
          if (ret < 0)
            {
              const int e = errno;
              if (e == EWOULDBLOCK || e == EINTR || e == EAGAIN)
                continue;
              out ("send()=%d:%d\n", ret, e);
            }
          //sess->state = BPS_SEND_ERROR;
        }
    }

  if (buf != bps_send_buf)
    free (buf);
  return NULL;
}

void *
bps_recv (void *arg)
{
  static char bps_recv_buf[BPS_MAX_LEN];

  struct bps_sess *sess = (struct bps_sess *) arg;
  const int sid = BPS_SESS_ID (sess);
  int fd, recved = 0;
  char *buf = malloc (bps.buf_size);
  fd_set readfds;
  int max_sd;
  out ("client recv\n");
  if (!buf)
    buf = bps_recv_buf;

  futex_wait (&sess->fd, -1);
  __sync_synchronize ();

  fd = sess->fd;
  while (1)
    {
      FD_ZERO (&readfds);
      FD_SET (fd, &readfds);
      max_sd = fd;
      if (select (max_sd + 1, &readfds, NULL, NULL, NULL) < 0)
        {
          perror ("select");
        }
      if (FD_ISSET (fd, &readfds))
        {
          while (sess->state == BPS_RUNNING)
            {
              int ret = _recv (fd, buf + recved, bps.buf_size - recved, 0);
              if (ret > 0)
                {
                  recved += ret;
                  bps.rec_now[sid].rcv += ret;
                  if (recved >= bps.msg_len)
                    recved -= bps.msg_len;
                }
              else
                {
                  if (ret < 0)
                    {
                      const int e = errno;
                      if (e == EWOULDBLOCK || e == EINTR || e == EAGAIN)
                        continue;
                      out ("recv()=%d:%d\n", ret, e);
                    }
                  //sess->state = BPS_RECV_ERROR;
                }
            }
        }
    }

  if (buf != bps_recv_buf)
    free (buf);
  return NULL;
}

void
bps_stop (struct bps_sess *sess)
{
  if (sess->state == BPS_RUNNING)
    sess->state = BPS_STOP;

  if (sess->send_tid)
    (void) pthread_join (sess->send_tid, NULL);
  if (sess->recv_tid)
    (void) pthread_join (sess->recv_tid, NULL);

  if (sess->recv_core >= 0)
    bps.bind_core |= (1 << sess->recv_core);
  if (sess->send_core >= 0)
    bps.bind_core |= (1 << sess->send_core);

  if (sess->fd >= 0)
    {
      _close (sess->fd);
      sess->fd = -1;
    }

  bps.sess_num--;

  sess->head.prev->head.next = sess->head.next;
  sess->head.next->head.prev = sess->head.prev;

  sess->head.next = bps.free_sess;
  bps.free_sess = sess;
}

struct bps_sess *
bps_start (int fd)
{
  int ret;
  struct bps_sess *sess;

  if (!bps.free_sess)
    {
      _close (fd);
      return NULL;
    }

  sess = bps.free_sess;
  bps.free_sess = sess->head.next;

  sess->fd = fd;
  sess->state = BPS_RUNNING;
  sess->index = (uint16_t) (++bps.global_index);
  sess->recv_core = sess->send_core = -1;
  sess->recv_tid = sess->send_tid = 0;

  ++bps.sess_num;

  sess->head.next = (struct bps_sess *) &bps.sess_head;
  sess->head.prev = bps.sess_head.prev;
  bps.sess_head.prev->head.next = sess;
  bps.sess_head.prev = sess;

  ret = set_nonblock (fd);
  ERR_GOTO (ret, ERR_EXIT, "fcntl(%d, F_SETFL, O_NONBLOCK)=%d:%d\n", fd, ret,
            errno);

  if (bps.io_mode & BPS_IO_SEND)
    {
      sess->send_core = bps_cpu ();
      sess->send_tid = lb_thread (bps_send, sess, "bps-send-%d", fd);
      ERR_GOTO (sess->send_tid == 0, ERR_EXIT, "lb_thread(send:%d)=0:%d\n",
                fd, errno);
      if (sess->send_core >= 0)
        {
          lb_setcpu (sess->send_tid, sess->send_core);
        }
    }

  if (bps.io_mode & BPS_IO_RECV)
    {
      sess->recv_core = bps_cpu ();
      sess->recv_tid = lb_thread (bps_recv, sess, "bps-recv-%d", fd);
      ERR_GOTO (sess->recv_tid == 0, ERR_EXIT, "lb_thread(recv:%d)=0:%d\n",
                fd, errno);
      if (sess->recv_core >= 0)
        {
          lb_setcpu (sess->recv_tid, sess->recv_core);
        }
    }

  if (BPS_SESS_ID (sess) > bps.max_sess_id)
    bps.max_sess_id = BPS_SESS_ID (sess);

  return sess;

ERR_EXIT:
  bps_stop (sess);
  return NULL;
}

void
bps_accept ()
{
  while (bps.state == BPS_RUNNING)
    {
      int ret, fd;
      struct bps_sess *sess;
      struct sockaddr_in addr = { 0 }, s_addr =
      {
      0};
      socklen_t len = sizeof (addr);

      fd = _accept (bps.listen_fd, (struct sockaddr *) &addr, &len);
      if (fd < 0)
        {
          if (!
              (errno == ETIMEDOUT || errno == EWOULDBLOCK || errno == EAGAIN))
            {
              wrn ("accept(%d)=%d:%d\n", bps.listen_fd, fd, errno);
            }
          return;
        }

      len = sizeof (s_addr);
      ret = _getsockname (fd, (struct sockaddr *) &s_addr, &len);
      if (ret)
        {
          _close (fd);
          wrn ("getsockname(%d)=%d:%d\n", fd, ret, errno);
          continue;
        }

      sess = bps_start (fd);
      if (sess)
        {
          out ("[%d:%d] accepted %s --> %s\n", sess->index, fd,
               f_inaddr (&addr), f_inaddr (&s_addr));
        }
      else
        {
          out ("[ERR:%d] accept %s --> %s FAILED\n", fd, f_inaddr (&addr),
               f_inaddr (&s_addr));
        }
    }
}

void
bps_output (uint16_t index, int fd, uint64_t nsec, struct bps_rec *rec)
{
  const int UBPS = bps.exact ? 1 : MB;
  const int UPPS = bps.exact ? 1 : KB;
  const int SBPS = bps.exact ? 14 : 6;
  const int SPPS = bps.exact ? 10 : 5;

  char buf[256];
  char *pos = buf;

  *pos++ = ' ';
  pos += r_uint (pos, lb_gdiv ((rec->rcv + rec->snd) * 8, nsec) / UBPS, SBPS);
  *pos++ = ' ';
  pos +=
    r_uint (pos, lb_gdiv ((rec->rcv + rec->snd), nsec * bps.msg_len) / UPPS,
            SPPS);
  *pos++ = ' ';
  *pos++ = '|';
  *pos++ = ' ';
  pos += r_uint (pos, lb_gdiv (rec->snd * 8, nsec) / UBPS, SBPS);
  *pos++ = ' ';
  pos += r_uint (pos, lb_gdiv (rec->snd, nsec * bps.msg_len) / UPPS, SPPS);
  *pos++ = ' ';
  *pos++ = '|';
  *pos++ = ' ';
  pos += r_uint (pos, lb_gdiv (rec->rcv * 8, nsec) / UBPS, SBPS);
  *pos++ = ' ';
  pos += r_uint (pos, lb_gdiv (rec->rcv, nsec * bps.msg_len) / UPPS, SPPS);

  if (index == 0)
    {
      if (fd > 60 * 60)
        pos +=
          sprintf (pos, " | %d:%02d:%02d", fd / 3600, fd % 3600 / 60,
                   fd % 60);
      else
        pos += sprintf (pos, " | %02d:%02d", fd / 60, fd % 60);
    }
  else
    {
      pos += sprintf (pos, " | %u-%d", index, fd);
    }

  *pos = 0;

  out ("%s\n", buf);
}

void
bps_report (const struct timespec *now)
{
  static const char *HEAD[] = {
    " T:mbps  kpps | S:mbps  kpps | R:mbps  kpps | info",
    "      total:bps 		pps |		send:bps 		pps |		recv:bps 	   pps | info"
  };
  static int report_set = 0;

  int i;
  struct bps_sess *sess;
  struct bps_rec rec, *last = bps.rec_now;
  uint64_t nsec = LB_SUB_NS (*now, bps.last_time);

  bps.rec_now = bps.rec_list[last == bps.rec_list[0] ? 1 : 0];

  lb_sleep (0, BPS_EXCH_DELAY * NSOFMS);        /* wait memory */

  rec.rcv = rec.snd = 0;
  for (i = 0; i <= bps.max_sess_id; ++i)
    {
      rec.rcv += last[i].rcv;
      rec.snd += last[i].snd;
    }

  if (rec.rcv == 0 && rec.snd == 0)
    {
      if (report_set != 0)
        {
          out ("\n");
          report_set = 0;
        }
      return;
    }

  if (report_set++ == 0)
    out ("%s\n", HEAD[bps.exact]);

  nsec = LB_SUB_NS (*now, bps.last_time);

  sess = bps.sess_head.next;
  while (sess != (struct bps_sess *) &bps.sess_head)
    {
      struct bps_sess *next = sess->head.next;

      if (bps.verbose)
        bps_output (sess->index, sess->fd, nsec, last + BPS_SESS_ID (sess));

      if (sess->state != BPS_RUNNING)
        bps_stop (sess);

      sess = next;
    }

  bps_output (0, (int) (LB_SUB_NS (*now, bps.begin_time) / NSOFS), nsec,
              &rec);

  (void) memset (last, 0, sizeof (struct bps_rec) * (bps.max_sess_id + 1));
}

void
bps_loop ()
{
  while (bps.state == BPS_RUNNING)
    {
      struct timespec now;

      LB_TIME (now);

      if (LB_CMP (now, bps.next_time) >= 0)
        {
          bps_report (&now);
          bps.last_time = now;
          bps.next_time.tv_sec += bps.report_time;
        }

      if (bps.client_mode)
        {
          if (LB_CMP_S (now, bps.begin_time, bps.test_time))
            {
              bps.state = BPS_STOP;
              break;
            }
        }
      else
        {
          bps_accept ();
        }

      lb_sleep (0, BPS_STAT_TIMER * NSOFMS);
    }
}

int
bps_server ()
{
  int ret;

  /* server socket listen */

  bps.listen_fd = _socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  ERR_RETURN (bps.listen_fd < 0, 1, "socket()=%d:%d\n", bps.listen_fd, errno);

  ret =
    _bind (bps.listen_fd, (struct sockaddr *) &bps.server_addr,
           sizeof (bps.server_addr));
  ERR_RETURN (ret, 1, "bind(%d)=%d:%d\n", bps.listen_fd, ret, errno);

  ret = _listen (bps.listen_fd, 10);
  ERR_RETURN (ret, 1, "listen(%d)=%d:%d\n", bps.listen_fd, ret, errno);

  ret = set_nonblock (bps.listen_fd);
  ERR_RETURN (ret, 1, "set_nonblock(%d) failed\n", bps.listen_fd);

  out ("[%d] listen on %s\n", bps.listen_fd, f_inaddr (&bps.server_addr));

  return 0;
}

int
bps_client ()
{
  int i, fd;

  for (i = 0; i < bps.parallel; ++i)
    {
      int ret;
      struct bps_sess *sess;
      struct sockaddr_in addr = { 0 };
      socklen_t len = sizeof (addr);

      fd = _socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
      ERR_RETURN (fd < 0, 1, "socket()=%d:%d\n", fd, errno);

      if (bps.client_bind)
        {
          ret =
            _bind (fd, (struct sockaddr *) &bps.bind_addr,
                   sizeof (bps.bind_addr));
          ERR_GOTO (ret, ERR_EXIT, "bind(%d, %s)=%d:%d\n", fd,
                    f_inaddr (&bps.bind_addr), ret, errno);
        }

      ret =
        _connect (fd, (struct sockaddr *) &bps.server_addr,
                  sizeof (bps.server_addr));
      ERR_GOTO (ret, ERR_EXIT, "connect(%d, %s)=%d:%d\n", fd,
                f_inaddr (&bps.server_addr), ret, errno);

      ret = _getsockname (fd, (struct sockaddr *) &addr, &len);
      ERR_GOTO (ret, ERR_EXIT, "getsockname(%d)=%d:%d\n", fd, ret, errno);

      sess = bps_start (fd);
      if (ret)
        {
          return 1;
        }

      out ("[%d:%d] connected %s --> %s\n", sess->index, fd, f_inaddr (&addr),
           f_inaddr (&bps.server_addr));
    }

  return 0;

ERR_EXIT:
  _close (fd);
  return 1;
}

void
bps_exit ()
{
  while (bps.sess_head.next != (struct bps_sess *) &bps.sess_head)
    {
      struct bps_sess *sess = bps.sess_head.next;

      bps_stop (sess);
    }

  if (bps.listen_fd >= 0)
    {
      _close (bps.listen_fd);
      bps.listen_fd = -1;
    }
}

int
bps_init ()
{
  int i;
  struct bps_sess *sess;

  bps.listen_fd = -1;
  bps.rec_now = bps.rec_list[0];

  if (bps.parallel == 0)
    bps.parallel = BPS_DEF_PARALLEL;
  if (bps.test_time == 0)
    bps.test_time = BPS_DEF_TIME;
  if (bps.report_time == 0)
    bps.report_time = BPS_DEF_REPORT_TIME;
  if (bps.io_mode == 0)
    bps.io_mode = BPS_IO_SEND | BPS_IO_RECV;
  if (bps.msg_len == 0)
    bps.msg_len = BPS_DEF_LEN;
  if (bps.buf_size < bps.msg_len)
    bps.buf_size = bps.msg_len;

  bps.free_sess = sess = bps.sess_list;
  for (i = 0; i < BPS_MAX_SESS - 1; ++i)
    {
      sess->head.next = sess + 1;
      sess++;
    }
  sess->head.next = NULL;

  bps.sess_head.next = bps.sess_head.prev =
    (struct bps_sess *) &bps.sess_head;

  LB_TIME (bps.begin_time);
  bps.last_time = bps.next_time = bps.begin_time;
  bps.next_time.tv_sec += bps.report_time;

  return 0;
}

#ifndef EXEC_BPS_
#define EXEC_BPS_

#define OPTIONS "i:l:B:cC:SRt:b:p:m:veh" DBGOPT

static const struct option options[] = {
  {"interval", 1, 0, 'i'},
  {"length", 1, 0, 'l'},
  {"buffer", 1, 0, 'B'},
  {"client", 0, 0, 'c'},
  {"core", 1, 0, 'C'},
  {"time", 1, 0, 't'},
  {"bind", 1, 0, 'b'},
  {"parallel", 1, 0, 'p'},
  {"send-only", 0, 0, 'S'},
  {"recv-only", 0, 0, 'R'},
  {"verbose", 0, 0, 'v'},
  {"exact", 0, 0, 'e'},
  {"help", 0, 0, 'h'},
  DBGOPT_LONG {0, 0, 0, 0}
};

void
bps_usage (const char *name)
{
  out ("USAGE: %s [OPTIONS] [SERVER-ADDRESS]	# %s version\n", name,
       VERSION_NAME);
  out (" Options:\n");
  out ("  -h, --help				help\n");
  out ("  -v, --verbose				show more statistics\n");
  out ("  -e, --exact				show exact value\n");
  out ("  -i, --interval=SECONDS	report time(default:%ds)\n",
       BPS_DEF_REPORT_TIME);
  out ("  -l, --length=LENGTH 		message length(default:%d max:%d)\n",
       BPS_DEF_LEN, BPS_MAX_LEN);
  out
    ("  -B, --buffer=BUFFER 		recv buffer size(default:LENGTH max:%d)\n",
     BPS_MAX_LEN);
  out
    ("  -C, --core=COREMASK		bound core mask HEX(default:0(no bind core))\n");
  out ("  -S, --send-only			only send\n");
  out ("  -R, --recv-only 			only receive\n");
  out ("  -c, --client 			client mode\n");
  out (" Client mode options:\n");
  out ("  -t, --time=SECOND 		test time(default:%ds)\n",
       BPS_DEF_TIME);
  out ("  -b, --bind=ADDRESS 		bind address\n");
  out
    ("  -p, --parallel=#			parallel number(default:%d max:%d)\n",
     BPS_DEF_PARALLEL, BPS_MAX_PARALLEL);
#ifdef DEBUG
  out ("  -D, --debug				show debug information\n");
#endif
  out ("  ADDRESS: X.X.X.X:PORT default port:%u\n", BPS_DEF_PORT);
}

int
bps_args (int argc, char *argv[])
{
  const char *end;
  int opt, index;

  bps.bind_addr.sin_family = AF_INET;
  bps.bind_addr.sin_addr.s_addr = INADDR_ANY;
  bps.bind_addr.sin_port = 0;

  bps.server_addr.sin_family = AF_INET;
  bps.server_addr.sin_addr.s_addr = INADDR_ANY;
  bps.server_addr.sin_port = htons (BPS_DEF_PORT);

  while (EOF != (opt = getopt_long (argc, argv, OPTIONS, options, &index)))
    {
      switch (opt)
        {
        case 'i':
          bps.report_time = atoi (optarg);
          break;
        case 'l':
          bps.msg_len = atoi (optarg);
          ERR_RETURN (bps.msg_len > BPS_MAX_LEN, 1,
                      "Message len must between 1 and %d\n", BPS_MAX_LEN);
          break;
        case 'B':
          bps.buf_size = atoi (optarg);
          break;
        case 'c':
          bps.client_mode = 1;
          break;
        case 'C':
          bps.bind_core = p_hex (optarg, &end);
          ERR_RETURN (!end
                      || *end, 1, "Invalid bind core mask '%s'\n", optarg);
          break;
        case 't':
          bps.test_time = atoi (optarg);
          break;
        case 'b':
          ERR_RETURN (p_addr (optarg, &bps.bind_addr), 1,
                      "Invalid bind address '%s'\n", optarg);
          bps.client_bind = 1;
          break;
        case 'p':
          bps.parallel = atoi (optarg);
          ERR_RETURN (bps.parallel > BPS_MAX_PARALLEL || bps.parallel <= 0, 1,
                      "Parallel must between 1 and %d\n", BPS_MAX_PARALLEL);
          break;
        case 'S':
          bps.io_mode = BPS_IO_SEND;
          break;
        case 'R':
          bps.io_mode = BPS_IO_RECV;
          break;
        case 'v':
          bps.verbose = 1;
          break;
        case 'e':
          bps.exact = 1;
          break;
#ifdef DEBUG
        case 'D':
          enable_debug = 1;
          break;
#endif
        case 'h':
          bps_usage (argv[0]);
          exit (0);
        case '?':
          err ("Invalid arguments\n");
          return 1;
        default:
          err ("Unknown option '%c'.\n", opt);
          return 1;
        }
    }

  if (optind == argc - 1)
    {
      ERR_RETURN (p_addr (argv[optind], &bps.server_addr), 1,
                  "Invalid server address '%s'\n", argv[optind]);
    }
  else if (optind < argc)
    {
      while (optind < argc)
        err ("Unknown argument '%s'\n", argv[optind++]);
      return 1;
    }
  else if (bps.client_mode)
    {
      bps.server_addr.sin_addr.s_addr = inet_addr ("127.0.0.1");
    }

  printf
    ("bps param: verbose %d\n exact %d\n client_mode %d\n client_bind %d\n  io_mode %d\n parallel %d\n \
		buf_size %d\n msg_len %d\n bind_core %lu\n report_time %d\n test_time %d\n bind_addr %x\n server_addr %x\n",
     bps.verbose, bps.exact, bps.client_mode, bps.client_bind, bps.io_mode, bps.parallel, bps.buf_size, bps.msg_len, bps.bind_core, bps.report_time, bps.test_time,
     bps.bind_addr.sin_addr.s_addr, bps.server_addr.sin_addr.s_addr);
  return 0;
}

void
bps_break (int s)
{
  if (bps.state < 0)
    exit (1);

  out ("\n");

  bps.state = BPS_BREAK;
}

void
bps_sigpipe (int s)
{
  DBG ("SIGPIPE\n");
}

void
bps_set_sig ()
{
  struct sigaction s = { 0 };

  (void) sigemptyset (&s.sa_mask);

  s.sa_flags = SA_NODEFER;
  s.sa_handler = (void *) bps_break;
  (void) sigaction (SIGINT, &s, NULL);
  (void) sigaction (SIGQUIT, &s, NULL);

  s.sa_handler = bps_sigpipe;
  (void) sigaction (SIGPIPE, &s, NULL);
}

#endif /* #ifndef EXEC_BPS_ */

int
main (int argc, char *argv[])
{
  int ret;
  enable_debug = 1;
  if (bps_args (argc, argv))
    return 1;

  if (bps_init ())
    return 1;

  bps_set_sig ();

  if (bps.client_mode)
    ret = bps_client ();
  else
    ret = bps_server ();

  if (!ret)
    bps_loop ();

  bps_exit ();

  return ret;
}
