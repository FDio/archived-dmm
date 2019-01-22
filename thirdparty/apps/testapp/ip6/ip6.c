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

#define IP6_BUF_MAX (32 * 1024)

#define IP6_DEF_SHOW 16
#define IP6_MAX_SHOW 1024

#define IP6_DEF_LEN 100
#define IP6_MAX_LEN (1024 * 1024)

#define IP6_DEF_NUM  -1
#define IP6_MAX_NUM INT32_MAX

#define IP6_DEF_DELAY 1
#define IP6_MAX_DELAY 100

struct ip6_var
{
  struct sockaddr_in6 s_addr;
  struct sockaddr_in6 c_addr;
  int client_bind;
  int is_client;
  int is_udp;
  int num;
  int delay;
  int len;
  int verbose;
  int show_len;

  int fd;
  int sfd;
  int epfd;

  char *buf;
};

struct ip6_var ip6 = { 0 };

#if 1

int
tcp_listen ()
{
  int ret;

  ip6.sfd = _socket (PF_INET6, SOCK_STREAM, IPPROTO_TCP);
  ERR_RETURN (!ip6.sfd, -1, "socket()=%s%d:%d%s\n", BR__, ip6.sfd, errno, CC);

  ret = _bind (ip6.sfd, (struct sockaddr *) &ip6.s_addr, sizeof (ip6.s_addr));
  ERR_RETURN (ret, ret, "bind(%d, %s)=%s%d:%d%s\n", ip6.sfd,
              f_in6addr (&ip6.s_addr), BR__, ret, errno, CC);

  ret = _listen (ip6.sfd, 100);
  ERR_RETURN (ret, ret, "listen(%d)=%s%d:%d%s\n", ip6.sfd,
              BR__, ret, errno, CC);

  out ("TCP server listen on %s\n", f_in6addr (&ip6.s_addr));

  return 0;
}

void
tcp_server ()
{
  if (tcp_listen ())
    return;

  while (1)
    {
      int recv_all = 0, sent_all = 0;
      struct sockaddr_in6 addr;
      socklen_t addr_len = sizeof (addr);

      ip6.fd = _accept (ip6.sfd, (struct sockaddr *) &addr, &addr_len);
      if (ip6.fd < 0)
        {
          out ("accept(%d)=%s%d:%d%s\n", ip6.sfd, BR__, ip6.fd, errno, CC);
          break;
        }

      out ("incoming %d from %s\n", ip6.fd, f_in6addr (&addr));

      while (1)
        {
          int recv_len, sent_len = 0, len, times = 0;

          recv_len = _recv (ip6.fd, ip6.buf, IP6_MAX_LEN, 0);
          if (recv_len == 0)
            break;
          if (recv_len < 0)
            {
              if (errno == EINTR)
                continue;
              out ("recv(%d)=%s%d:%d%s\n", ip6.fd, BR__, recv_len, errno, CC);
              break;
            }
          recv_all += recv_len;
          if (ip6.verbose)
            out ("recv: %d = %d\n", recv_all, recv_len);

        SENDING:
          len = _send (ip6.fd, ip6.buf + sent_len, recv_len - sent_len, 0);
          if (len == 0)
            break;
          if (len < 0)
            {
              if (errno == EINTR)
                continue;
              out ("send(%d, %d)=%s%d:%d%s\n", ip6.fd, recv_len - sent_len,
                   BR__, len, errno, CC);
              break;
            }

          times++;
          sent_len += len;
          sent_all += len;
          if (ip6.verbose)
            out ("sent: %d = %d + %d\n", sent_all, sent_len, len);

          if (sent_len < recv_len)
            goto SENDING;

          if (times > 1)
            out ("%d replied in %d times\n", sent_len, times);
          else
            out ("%d replied\n", sent_len);
        }

      out ("closing %d --- input:%d output:%d\n", ip6.fd, recv_all, sent_all);
      _close (ip6.fd);
      ip6.fd = -1;
    }

  err ("TCP server break\n");
}

int
tcp_connect ()
{
  int ret;

  ip6.fd = _socket (PF_INET6, SOCK_STREAM, IPPROTO_TCP);
  ERR_RETURN (!ip6.fd, -1,
              "socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP)=%s%d:%d%s\n", BR__,
              ip6.fd, errno, CC);

  if (ip6.client_bind)
    {
      ret =
        _bind (ip6.fd, (struct sockaddr *) &ip6.c_addr, sizeof (ip6.c_addr));
      ERR_RETURN (ret, ret, "bind(%d, %s)=%s%d:%d%s\n", ip6.fd,
                  f_in6addr (&ip6.c_addr), BR__, ret, errno, CC);
    }

  ret =
    _connect (ip6.fd, (struct sockaddr *) &ip6.s_addr, sizeof (ip6.s_addr));
  ERR_RETURN (ret, ret, "connect(%d, %s)=%s%d:%d%s\n", ip6.fd,
              f_in6addr (&ip6.s_addr), BR__, ret, errno, CC);

  if (!ip6.client_bind)
    {
      socklen_t len = sizeof (ip6.c_addr);
      ret = _getsockname (ip6.fd, (struct sockaddr *) &ip6.c_addr, &len);
      ERR_RETURN (ret, ret, "getsockname()=%d:%d\n", ret, errno);
    }

  out ("connected %d from %s to %s\n", ip6.fd,
       f_in6addr (&ip6.c_addr), f_in6addr (&ip6.s_addr));

  return 0;
}

void
tcp_client ()
{
  int i, count = 0, sent_all = 0, recv_all = 0, sent_num = 0, recv_num = 0;
const struct timespec delay = { tv_sec: ip6.delay /* / 1000 */ , tv_nsec:      /*(ip6.delay % 1000) * 1000 * 100 */ 0
  };

  if (tcp_connect ())
    return;

  for (i = 0; i < ip6.len; ++i)
    ip6.buf[i] = (char) i;

  while (ip6.num != 0)
    {
      int len, recv_len = 0, sent_len = 0, recv_times = 0, send_times = 0;

    SENDING:
      len = _send (ip6.fd, ip6.buf + sent_len, ip6.len - sent_len, 0);
      if (len == 0)
        break;
      if (len < 0)
        {
          if (errno == EINTR)
            continue;
          out ("send(%d, %d)=%s%d:%d%s\n", ip6.fd, ip6.len - sent_len, BR__,
               len, errno, CC);
          break;
        }

      sent_len += len;
      sent_all += len;
      if (ip6.verbose)
        out ("sent: %d = %d + %d\n", sent_all, sent_len, len);
      if (sent_len < ip6.len)
        goto SENDING;
      sent_num++;

    RECVING:
      len = _recv (ip6.fd, ip6.buf + recv_len, IP6_MAX_LEN - recv_len, 0);
      if (len == 0)
        break;
      if (len < 0)
        {
          if (errno == EINTR)
            continue;
          out ("recv(%d)=%s%d:%d%s\n", ip6.fd, BR__, len, errno, CC);
          break;
        }
      recv_len += len;
      recv_all += len;
      if (ip6.verbose)
        out ("recv: %d = %d + %d\n", recv_all, recv_len, len);
      if (recv_len < sent_len)
        goto RECVING;
      recv_num++;

      out ("%d replied", sent_len);
      if (send_times > 1)
        out (" %d sending", send_times);
      if (recv_times > 1)
        out (" %d receiving", recv_times);

      for (i = 0; i < recv_len; ++i)
        {
          if (ip6.buf[i] != (char) i)
            {
              out (" data error [%d]:0x%02x != %02x", i, ip6.buf[i],
                   i & 0xFF);
              for (; i < recv_len; ++i)
                ip6.buf[i] = (char) i;
              break;
            }
        }

      out ("\n");

      if (ip6.num > 0 && sent_num >= ip6.num)
        break;

      if (ip6.delay)
        {
          (void) nanosleep (&delay, NULL);
        }
    }

  out ("closing %d\n", ip6.fd);

  if (sent_num)
    {
      out ("--- %s -> %s TCP ping statistics ---\n",
           f_in6addr (&ip6.c_addr), f_in6addr (&ip6.s_addr));
      out
        ("%d output, %d input, %d packets transmitted, %d received, %d%% packet loss\n",
         sent_all, recv_all, sent_num, recv_num,
         (sent_num - recv_num) * 100 / sent_num);
    }
}

#endif
#if 1

void
udp_recv_show (char *buf, int len)
{
  int i, dot = 0;
  char co[256];

  co_init (co, sizeof (co));

  if (len > ip6.show_len)
    {
      len = ip6.show_len;
      dot = 1;
    }

  if (len > 16)
    co_app_ch (co, '\n');

  for (i = 0; i < len; ++i)
    {
      char ch;

      co_ch_if (i && (i % 32) == 0, co, '\n');
      co_ch_if ((i % 16) == 0, co, ' ');
      co_ch_if ((i % 4) == 0, co, ' ');

      ch = buf[i] >> 4;
      ch += (ch > 9 ? 'A' : '0');
      co_app_ch (co, ch);
      ch = buf[i] & 0xF;
      ch += (ch > 9 ? 'A' : '0');
      co_app_ch (co, ch);
    }

  if (dot)
    co_append (co, 6, " ...\n");
  else
    co_app_ch (co, '\n');

  co_flush (co);
}

void
udp_server ()
{
  int ret;
  uint32_t count = 0;

  ip6.fd = _socket (PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (ip6.fd < 0)
    {
      err ("socket()=%d:%d\n", ip6.fd, errno);
      return;
    }

  ret = _bind (ip6.fd, (struct sockaddr *) &ip6.s_addr, sizeof (ip6.s_addr));
  if (ret)
    {
      err ("bind(%d, %s)=%d:%d\n", ip6.fd, f_in6addr (&ip6.s_addr), ret,
           errno);
      return;
    }

  out ("UDP server bound %s\n", f_in6addr (&ip6.s_addr));

  while (1)
    {
      struct sockaddr_in6 addr;
      socklen_t addrlen = sizeof (addr);
      int recv_len, sent_len;

      recv_len =
        _recvfrom (ip6.fd, ip6.buf, IP6_BUF_MAX, 0, (struct sockaddr *) &addr,
                   &addrlen);

      if (recv_len == 0)
        {
          out ("recvfrom()=0 --> exit\n");
          break;
        }
      if (recv_len < 0)
        {
          if (errno != EINTR)
            out ("recvfrom()=%s%d:%d%s\n", FR__, recv_len, errno, CC);
          continue;
        }

    SENDING:
      sent_len =
        _sendto (ip6.fd, ip6.buf, recv_len, 0, (struct sockaddr *) &addr,
                 sizeof (addr));
      if (sent_len == 0)
        break;
      if (sent_len < 0)
        {
          if (errno == EINTR)
            goto SENDING;
          out ("sendto(%d, %s)=%s%d:%d%s\n", recv_len, f_in6addr (&addr),
               FR__, sent_len, errno, CC);
          continue;
        }

      out ("%d received from %s", recv_len, f_in6addr (&addr));
      if (recv_len == sent_len)
        out ("\n");
      else
        out (", sent %s%d%s\n", FR__, sent_len, CC);
    }

  err ("UDP server break\n");
}

void
udp_client ()
{
  int ret, i, sent_num = 0, recv_num = 0;
const struct timespec delay = { tv_sec: ip6.delay /* / 1000 */ , tv_nsec:      /*(ip6.delay % 1000) * 1000 * 100 */ 0
  };

  ip6.fd = _socket (PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (ip6.fd < 0)
    {
      err ("socket()=%d:%d\n", ip6.fd, errno);
      return;
    }

  if (ip6.client_bind)
    {
      ret =
        _bind (ip6.fd, (struct sockaddr *) &ip6.c_addr,
               sizeof (struct sockaddr_in6));
      if (ret)
        {
          err ("bind(%d, %s)=%d:%d\n", ip6.fd, f_in6addr (&ip6.c_addr), ret,
               errno);
          return;
        }
      out ("UDP client bind %s\n", f_in6addr (&ip6.c_addr));
    }

  out ("UDP client ping %s size:%d\n", f_in6addr (&ip6.s_addr), ip6.len);

  for (i = 0; i < ip6.len; ++i)
    ip6.buf[i] = (char) i;

  while (1)
    {
      struct sockaddr_in6 addr;
      socklen_t addrlen = sizeof (addr);
      int sent_len, recv_len;

      sent_len =
        _sendto (ip6.fd, ip6.buf, ip6.len, 0,
                 (const struct sockaddr *) &ip6.s_addr, addrlen);
      if (sent_len == 0)
        break;
      if (sent_len < 0)
        {
          if (errno != EINTR)
            out ("sendto(%d, %s)=%s%d:%d%s\n", ip6.len,
                 f_in6addr (&ip6.s_addr), FR__, sent_len, errno, CC);
          continue;
        }
      sent_num++;
      if (sent_len != ip6.len)
        {
          out ("sendto(%d, %s)=%s%d:%d%s\n", ip6.len, f_in6addr (&ip6.s_addr),
               FR__, sent_len, errno, CC);
        }
    RECVING:
      recv_len =
        recvfrom (ip6.fd, ip6.buf, IP6_MAX_LEN, 0, (struct sockaddr *) &addr,
                  &addrlen);
      if (recv_len == 0)
        break;
      if (recv_len < 0)
        {
          if (errno == EINTR)
            goto RECVING;
          out ("recvfrom()=%s%d:%d%s\n", FR__, recv_len, errno, CC);
          continue;
        }

      recv_num++;
      out ("%d bytes from %s", recv_len, f_in6addr (&addr));

      if (sent_len != recv_len)
        out (" recv_len != sent_len %d", sent_len);

      if (addr.sin6_port != ip6.s_addr.sin6_port ||
          addr.sin6_addr.s6_addr32[0] != ip6.s_addr.sin6_addr.s6_addr32[0] ||
          addr.sin6_addr.s6_addr32[1] != ip6.s_addr.sin6_addr.s6_addr32[1] ||
          addr.sin6_addr.s6_addr32[2] != ip6.s_addr.sin6_addr.s6_addr32[2] ||
          addr.sin6_addr.s6_addr32[3] != ip6.s_addr.sin6_addr.s6_addr32[3])
        {
          out (" address error");
        }

      for (i = 0; i < recv_len; ++i)
        {
          if (ip6.buf[i] != (char) i)
            {
              out ("data error [%d]:0x%02x != %02x", i, ip6.buf[i], i & 0xFF);
              for (; i < ip6.len; ++i)
                ip6.buf[i] = (char) i;
              break;
            }
        }

      out ("\n");

      if (ip6.num > 0 && sent_num >= ip6.num)
        break;

      if (ip6.delay)
        {
          (void) nanosleep (&delay, NULL);
        }
    }

  if (sent_num)
    {
      out ("--- UDP ping %s statistics ---\n", f_in6addr (&ip6.s_addr));
      out ("%d packets transmitted, %d received, %d%% packet loss\n",
           sent_num, recv_num, (sent_num - recv_num) * 100 / sent_num);
    }
}

#endif

int
ip6_start ()
{
  ip6.fd = -1;
  ip6.sfd = -1;
  ip6.epfd = -1;

  if (ip6.num == 0)
    ip6.num = IP6_DEF_NUM;

  ip6.s_addr.sin6_family = AF_INET6;
  ip6.c_addr.sin6_family = AF_INET6;

  ip6.buf = malloc (IP6_MAX_LEN);
  ERR_RETURN (!ip6.buf, -1, "Out of memory");

  return 0;
}

void
ip6_exit ()
{
  FD_CLOSE (ip6.fd);
  FD_CLOSE (ip6.sfd);
  FD_CLOSE (ip6.epfd);

  BUF_FREE (ip6.buf);
}

#define IP6_OPTIONS "b:cun:d:l:o:" DBGOPT "vh"

static const struct option ip6_options[] = {
  {"bind", 1, 0, 'b'},
  {"client", 0, 0, 'c'},
  {"udp", 0, 0, 'u'},
  {"number", 1, 0, 'n'},
  {"delay", 1, 0, 'd'},
  {"len", 1, 0, 'l'},
  {"output", 1, 0, 'o'},
  DBGOPT_LONG {"verbose", 0, 0, 'v'},
  {"help", 0, 0, 'h'},
  {0, 0, 0, 0}
};

void
ip6_usage (const char *name)
{
  out ("USAGE: %s [OPTIONS] SERVER-ADDRESS   # %s version\n", name,
       VERSION_NAME);
  out (" Options:\n");
  out ("  -b, --bind IP.PORT 		  bind address\n");
  out ("  -c, --client 		      client mode\n");
  out ("  -u, --udp 		          udp mode\n");
  out ("  -n, --number # 		   C  packet number(default:LOOP)\n");
  out
    ("  -d, --delay #		   C  seconds wait send next packet(default:1, 0: no delay)\n");
  out ("  -l, --length #          C  data length(default:%u)\n", IP6_DEF_LEN);
  out
    ("  -o, --output #		      show received data(default:%u)\n",
     IP6_DEF_SHOW);
#ifdef DEBUG
  out ("  -D, --debug 	      		  show debug information\n");
#endif
  out ("  -v, --verbose	 		  show thread statistics\n");
  out ("  -h, --help 		 		  help\n");
}

int
ip6_args (int argc, char *argv[])
{
  int ret, opt, index;

  ip6.delay = IP6_DEF_DELAY;
  ip6.len = IP6_DEF_LEN;

  while (EOF !=
         (opt = getopt_long (argc, argv, IP6_OPTIONS, ip6_options, &index)))
    {
      const char *end;

      switch (opt)
        {
        case 'b':
          ret = p_addr6 (optarg, &ip6.c_addr);
          ERR_RETURN (ret, -1, "Invalid client set '%s'\n", optarg);
          ip6.client_bind = 1;
          break;
        case 'c':
          ip6.is_client = 1;
          break;

        case 'u':
          ip6.is_udp = 1;
          break;

        case 'n':
          ip6.num = p_uint (optarg, IP6_MAX_NUM, &end);
          ERR_RETURN (!end || *end, -1, "Invalid number '%s'\n", optarg);
          break;
        case 'd':
          ip6.delay = (int) p_int (optarg, IP6_MAX_DELAY, &end);
          ERR_RETURN (!end || *end, -1, "Invalid delay '%s'\n", optarg);
          break;

        case 'l':
          ip6.len = (int) p_int (optarg, IP6_MAX_LEN, &end);
          ERR_RETURN (!end || *end, -1, "Invalid query '%s'\n", optarg);
          break;

        case 'o':
          ip6.show_len = (int) p_int (optarg, IP6_MAX_SHOW, &end);
          ERR_RETURN (!end || *end, -1, "Invalid reply '%s'\n", optarg);
          break;

        case 'v':
          ip6.verbose = 1;
          break;

#ifdef DEBUG
        case 'D':
          enable_debug = 1;
          break;
#endif
        case 'h':
          ip6_usage (argv[0]);
          exit (0);
        case '?':
          err ("Invalid arguments\n");
          return -1;
        default:
          err ("Unknown option '%c'.\n", opt);
          return -1;
        }
    }

  if (optind == argc - 1)
    {
      ERR_RETURN (p_addr6 (argv[optind], &ip6.s_addr), -1,
                  "Invalid server address '%s'\n", argv[optind]);
    }
  else if (optind < argc)
    {
      while (optind < argc)
        err ("Unknown argument '%s'\n", argv[optind++]);
      return -1;
    }
  else
    {
      err ("NO server address\n");
      return -1;
    }

  return 0;
}

void
ip6_break (int s)
{
  DBG (" SIGNALED %d\n", s);
  out ("\n");

  ip6_exit ();
  exit (0);
}

void
ip6_sigpipe (int s)
{
  DBG ("SIGPIPE\n");
}

int
ip6_init ()
{
  struct sigaction s = { 0 };

  (void) sigemptyset (&s.sa_mask);

  s.sa_flags = SA_NODEFER;
  s.sa_handler = (void *) ip6_break;
  (void) sigaction (SIGINT, &s, NULL);
  (void) sigaction (SIGQUIT, &s, NULL);

  s.sa_handler = ip6_sigpipe;
  (void) sigaction (SIGPIPE, &s, NULL);

//         lb_sigsegv_setup();

  return 0;
}

int
main (int argc, char *argv[])
{
  if (ip6_init ())
    return 1;

  if (ip6_args (argc, argv))
    return 1;

  ip6_start ();

  if (ip6.is_client)
    {
      if (ip6.is_udp)
        udp_client ();
      else
        tcp_client ();
    }
  else
    {
      if (ip6.is_udp)
        udp_server ();
      else
        tcp_server ();
    }

  ip6_exit ();
  return 0;
}
