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

#define TEST_ASSERT(cond) do { if(!(cond)) err("%s\n", #cond); } while(0)

int
test_v6_udp (int argc, const char *argv[])
{
  int fd, ret;
  struct sockaddr_in6 addr = { 0 };
  struct sockaddr_in6 out = { 0 };
  socklen_t len = sizeof (out);
  const char *ip = argv[1];

  fd = _socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  ERR_RETURN (fd < 0, -1, "socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)=%d:%d\n",
              fd, errno);

  ret = inet_pton (AF_INET6, ip, &addr.sin6_addr);
  ERR_GOTO (ret != 1, CLEAN, "inet_pton(AF_INET6, %s)=%d:%d\n", ip, ret,
            errno);

  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons (54321);
  ret = _bind (fd, (struct sockaddr *) &addr, sizeof (addr));
  ERR_GOTO (ret < 0, CLEAN, "bind(%d, %s, %ld)=%d:%d\n", fd,
            f_in6addr (&addr), sizeof (addr), ret, errno);

  ret = _getsockname (fd, (struct sockaddr *) &out, &len);
  ERR_GOTO (ret < 0, CLEAN, "getsockname(%d, %s, %d)=%d:%d\n", fd,
            f_in6addr (&out), len, ret, errno);
  TEST_ASSERT (out.sin6_family == AF_INET6);
  TEST_ASSERT (out.sin6_addr.s6_addr32[0] == addr.sin6_addr.s6_addr32[0]);
  TEST_ASSERT (out.sin6_addr.s6_addr32[1] == addr.sin6_addr.s6_addr32[1]);
  TEST_ASSERT (out.sin6_addr.s6_addr32[2] == addr.sin6_addr.s6_addr32[2]);
  TEST_ASSERT (out.sin6_addr.s6_addr32[3] == addr.sin6_addr.s6_addr32[3]);
  TEST_ASSERT (out.sin6_port == addr.sin6_port);

  ret = _close (fd);
  if (ret)
    err ("close(%d)=%d:%d\n", fd, ret, errno);

  return ret;

CLEAN:
  (void) _close (fd);
  return -1;
}

int
test_v4_udp (int argc, const char *argv[])
{
  int fd, ret;
  struct sockaddr_in addr = { 0 };
  struct sockaddr_in out = { 0 };
  socklen_t len = sizeof (out);
  const char *ip = argv[1];

  fd = _socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  ERR_RETURN (fd < 0, fd, "socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)=%d:%d\n",
              fd, errno);

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr (ip);
  addr.sin_port = htons (12345);
  ret = _bind (fd, (struct sockaddr *) &addr, sizeof (addr));
  ERR_GOTO (ret < 0, CLEAN, "bind(%d, %s, %ld)=%d:%d\n", fd, f_inaddr (&addr),
            sizeof (addr), ret, errno);

  ret = _getsockname (fd, (struct sockaddr *) &out, &len);
  ERR_GOTO (ret < 0, CLEAN, "getsockname(%d, %s, %d)=%d:%d\n", fd,
            f_inaddr (&out), len, ret, errno);
  TEST_ASSERT (out.sin_family == AF_INET);
  TEST_ASSERT (out.sin_addr.s_addr == addr.sin_addr.s_addr);
  TEST_ASSERT (out.sin_port == addr.sin_port);

  ret = _close (fd);
  if (ret)
    err ("close(%d)=%d:%d\n", fd, ret, errno);

  return ret;

CLEAN:
  (void) _close (fd);
  return -1;
}

int
test_v4_tcp (int argc, const char *argv[])
{
  int sfd, cfd, afd, ret;
  struct sockaddr_in saddr = { 0 }, caddr =
  {
  0}, aaddr =
  {
  0}, out =
  {
  0};
  socklen_t len;
  const char *ip = argv[1];

  sfd = _socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  ERR_RETURN (sfd < 0, sfd,
              "sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)=%d:%d\n", sfd,
              errno);

  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = inet_addr (ip);
  saddr.sin_port = htons (23456);
  ret = _bind (sfd, (struct sockaddr *) &saddr, sizeof (saddr));
  ERR_GOTO (ret < 0, CLEAN_S, "bind(%d, %s, %ld)=%d:%d\n", sfd,
            f_inaddr (&saddr), sizeof (saddr), ret, errno);

  ret = _listen (sfd, 100);
  ERR_GOTO (ret < 0, CLEAN_S, "listen(%d, 100)=%d:%d\n", sfd, ret, errno);

  cfd = _socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  ERR_GOTO (cfd < 0, CLEAN_S,
            "cfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)=%d:%d\n", cfd,
            errno);

  ret = _connect (cfd, (struct sockaddr *) &saddr, sizeof (saddr));
  ERR_GOTO (ret < 0, CLEAN_C, "connect(%d, %s, %ld)=%d:%d\n", cfd,
            f_inaddr (&saddr), sizeof (saddr), ret, errno);

  len = sizeof (caddr);
  ret = _getsockname (cfd, (struct sockaddr *) &caddr, &len);
  TEST_ASSERT (ret == 0);
  TEST_ASSERT (len == sizeof (caddr));

  len = sizeof (aaddr);
  afd = _accept (sfd, (struct sockaddr *) &aaddr, &len);
  ERR_GOTO (ret < 0, CLEAN_C, "accept(%d, %s, %d)=%d:%d\n", sfd,
            f_inaddr (&aaddr), len, ret, errno);
  TEST_ASSERT (len == sizeof (caddr));

  len = sizeof (out);
  ret = _getsockname (afd, (struct sockaddr *) &out, &len);
  TEST_ASSERT (ret == 0);
  TEST_ASSERT (len == sizeof (out));
  TEST_ASSERT (out.sin_family == AF_INET);
  TEST_ASSERT (out.sin_addr.s_addr == saddr.sin_addr.s_addr);
  TEST_ASSERT (out.sin_port == saddr.sin_port);

  len = sizeof (out);
  ret = _getpeername (afd, (struct sockaddr *) &out, &len);
  TEST_ASSERT (ret == 0);
  TEST_ASSERT (len == sizeof (out));
  TEST_ASSERT (out.sin_family == AF_INET);
  TEST_ASSERT (out.sin_addr.s_addr == caddr.sin_addr.s_addr);
  TEST_ASSERT (out.sin_port == caddr.sin_port);

  ret = _close (afd);
  TEST_ASSERT (ret == 0);

  ret = _close (cfd);
  TEST_ASSERT (ret == 0);

  ret = _close (sfd);
  TEST_ASSERT (ret == 0);

  return ret;

CLEAN:
  (void) _close (afd);
CLEAN_C:
  (void) _close (cfd);
CLEAN_S:
  (void) _close (sfd);
  return -1;
}

int
v6_udp_close_select (int argc, const char *argv[])
{
  int fd, ret;
  struct sockaddr_in6 addr = { 0 };
  struct sockaddr_in6 out = { 0 };
  socklen_t len = sizeof (out);
  const char *ip = argv[1];
  const char *port = argv[2];

  fd = _socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  ERR_RETURN (fd < 0, -1, "socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)=%d:%d\n",
              fd, errno);

  ret = inet_pton (AF_INET6, ip, &addr.sin6_addr);
  ERR_GOTO (ret != 1, CLEAN, "inet_pton(AF_INET6, %s)=%d:%d\n", ip, ret,
            errno);

  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons (atoi (port));
  ret = _bind (fd, (struct sockaddr *) &addr, sizeof (addr));
  ERR_GOTO (ret < 0, CLEAN, "bind(%d, %s, %ld)=%d:%d\n", fd,
            f_in6addr (&addr), sizeof (addr), ret, errno);

  ret = _close (fd);
  if (ret)
    err ("close(%d)=%d:%d\n", fd, ret, errno);

  {
    fd_set rfds, wfds, efds;
    int nfds = fd + 1;
    FD_ZERO (&rfds);
    FD_SET (fd, &rfds);
    FD_ZERO (&wfds);
    FD_SET (fd, &wfds);
    FD_ZERO (&efds);
    FD_SET (fd, &efds);
    ret = select (nfds, &rfds, &wfds, &efds, NULL);
    int err = errno;
    TEST_ASSERT (ret == -1);
    TEST_ASSERT (err == EBADF);
  }

  return 0;

CLEAN:
  (void) _close (fd);
  return -1;
}

int
v6_tcp_server_listen (int argc, const char *argv[])
{
  return -1;
}

int
v6_tcp_server_shutdown_rd (int argc, const char *argv[])
{
  int sfd = -1, afd = -1, ret;
  struct sockaddr_in6 saddr = { 0 }, aaddr =
  {
  0};
  socklen_t len;
  const char *ip = argv[1];
  const char *port = argv[2];

  sfd = _socket (PF_INET6, SOCK_STREAM, IPPROTO_TCP);
  ERR_RETURN (sfd < 0, sfd,
              "socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)=%d:%d\n", sfd,
              errno);

  saddr.sin6_family = AF_INET6;
  ret = inet_pton (AF_INET6, ip, &saddr.sin6_addr);
  ERR_GOTO (ret != 1, CLEAN_S,
            "inet_pton(AF_INET6, ip=\"%s\", &saddr.sin6_addr)=%d:%d\n", ip,
            ret, errno);
  saddr.sin6_port = htons (atoi (port));

  ret = _bind (sfd, (struct sockaddr *) &saddr, sizeof (saddr));
  ERR_GOTO (ret < 0, CLEAN_S, "bind(%d, %s, %ld)=%d:%d\n", sfd,
            f_in6addr (&saddr), sizeof (saddr), ret, errno);

  ret = _listen (sfd, 100);
  ERR_GOTO (ret < 0, CLEAN_S, "listen(%d, 100)=%d:%d\n", sfd, ret, errno);

  len = sizeof (aaddr);
  afd = _accept (sfd, (struct sockaddr *) &aaddr, &len);
  ERR_GOTO (ret < 0, CLEAN_S, "accept(%d, %s, %d)=%d:%d\n", sfd,
            f_in6addr (&aaddr), len, ret, errno);

  out ("accept(sfd=%d, addr=%s, len=%d)=%d\n", sfd, f_in6addr (&aaddr), len,
       afd);

  ret = _shutdown (afd, SHUT_RD);
  ERR_GOTO (ret != 0, CLEAN, "shutdown(afd=%d, SHUT_RD)=%d:%d\n", afd, ret,
            errno);

  out ("shutdown(afd=%d, SHUT_RD) ok --> sleep(10)\n", afd);
  sleep (10);

  out ("closing\n");

  ret = _close (afd);
  TEST_ASSERT (ret == 0);

  ret = _close (sfd);
  TEST_ASSERT (ret == 0);

  return ret;

CLEAN:
  (void) _close (afd);
CLEAN_S:
  (void) _close (sfd);
  return -1;
}

int
v6_tcp_server_shutdown_wr (int argc, const char *argv[])
{
  int sfd = -1, afd = -1, ret;
  struct sockaddr_in6 saddr = { 0 }, aaddr =
  {
  0};
  socklen_t len;
  const char *ip = argv[1];
  const char *port = argv[2];

  sfd = _socket (PF_INET6, SOCK_STREAM, IPPROTO_TCP);
  ERR_RETURN (sfd < 0, sfd,
              "socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)=%d:%d\n", sfd,
              errno);

  saddr.sin6_family = AF_INET6;
  ret = inet_pton (AF_INET6, ip, &saddr.sin6_addr);
  ERR_GOTO (ret != 1, CLEAN_S,
            "inet_pton(AF_INET6, ip=\"%s\", &saddr.sin6_addr)=%d:%d\n", ip,
            ret, errno);
  saddr.sin6_port = htons (atoi (port));

  ret = _bind (sfd, (struct sockaddr *) &saddr, sizeof (saddr));
  ERR_GOTO (ret < 0, CLEAN_S, "bind(%d, %s, %ld)=%d:%d\n", sfd,
            f_in6addr (&saddr), sizeof (saddr), ret, errno);

  ret = _listen (sfd, 100);
  ERR_GOTO (ret < 0, CLEAN_S, "listen(%d, 100)=%d:%d\n", sfd, ret, errno);

  len = sizeof (aaddr);
  afd = _accept (sfd, (struct sockaddr *) &aaddr, &len);
  ERR_GOTO (ret < 0, CLEAN_S, "accept(%d, %s, %d)=%d:%d\n", sfd,
            f_in6addr (&aaddr), len, ret, errno);

  out ("accept(sfd=%d, addr=%s, len=%d)=%d\n", sfd, f_in6addr (&aaddr), len,
       afd);

  ret = _shutdown (afd, SHUT_WR);
  ERR_GOTO (ret != 0, CLEAN, "shutdown(afd=%d, SHUT_WR)=%d:%d\n", afd, ret,
            errno);

  out ("shutdown(afd=%d, SHUT_WR) ok --> sleep(10)\n", afd);
  sleep (10);

  out ("closing\n");

  ret = _close (afd);
  TEST_ASSERT (ret == 0);

  ret = _close (sfd);
  TEST_ASSERT (ret == 0);

  return ret;

CLEAN:
  (void) _close (afd);
CLEAN_S:
  (void) _close (sfd);
  return -1;
}

int
v6_tcp_server_shutdown_rdwr (int argc, const char *argv[])
{
  int sfd = -1, afd = -1, ret;
  struct sockaddr_in6 saddr = { 0 }, aaddr =
  {
  0};
  socklen_t len;
  const char *ip = argv[1];
  const char *port = argv[2];

  sfd = _socket (PF_INET6, SOCK_STREAM, IPPROTO_TCP);
  ERR_RETURN (sfd < 0, sfd,
              "socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)=%d:%d\n", sfd,
              errno);

  saddr.sin6_family = AF_INET6;
  ret = inet_pton (AF_INET6, ip, &saddr.sin6_addr);
  ERR_GOTO (ret != 1, CLEAN_S,
            "inet_pton(AF_INET6, ip=\"%s\", &saddr.sin6_addr)=%d:%d\n", ip,
            ret, errno);
  saddr.sin6_port = htons (atoi (port));

  ret = _bind (sfd, (struct sockaddr *) &saddr, sizeof (saddr));
  ERR_GOTO (ret < 0, CLEAN_S, "bind(%d, %s, %ld)=%d:%d\n", sfd,
            f_in6addr (&saddr), sizeof (saddr), ret, errno);

  ret = _listen (sfd, 100);
  ERR_GOTO (ret < 0, CLEAN_S, "listen(%d, 100)=%d:%d\n", sfd, ret, errno);

  len = sizeof (aaddr);
  afd = _accept (sfd, (struct sockaddr *) &aaddr, &len);
  ERR_GOTO (ret < 0, CLEAN_S, "accept(%d, %s, %d)=%d:%d\n", sfd,
            f_in6addr (&aaddr), len, ret, errno);

  out ("accept(sfd=%d, addr=%s, len=%d)=%d\n", sfd, f_in6addr (&aaddr), len,
       afd);

  ret = _shutdown (afd, SHUT_RDWR);
  ERR_GOTO (ret != 0, CLEAN, "shutdown(afd=%d, SHUT_RDWR)=%d:%d\n", afd, ret,
            errno);

  out ("shutdown(afd=%d, SHUT_WR) ok --> sleep(10)\n", afd);
  sleep (10);

  out ("closing\n");

  ret = _close (afd);
  TEST_ASSERT (ret == 0);

  ret = _close (sfd);
  TEST_ASSERT (ret == 0);

  return ret;

CLEAN:
  (void) _close (afd);
CLEAN_S:
  (void) _close (sfd);
  return -1;
}

int
v6_tcp_client_s (int argc, const char *argv[])
{
  int cfd = -1, ret;
  struct sockaddr_in6 saddr = { 0 };
  socklen_t len;
  char buf[10] = { 'X', 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  const char *ip = argv[1];
  const char *port = argv[2];

  cfd = _socket (PF_INET6, SOCK_STREAM, IPPROTO_TCP);
  ERR_RETURN (cfd < 0, cfd,
              "socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)=%d:%d\n", cfd,
              errno);

  saddr.sin6_family = AF_INET6;
  ret = inet_pton (AF_INET6, ip, &saddr.sin6_addr);
  ERR_GOTO (ret != 1, CLEAN,
            "inet_pton(AF_INET6, ip=\"%s\", &saddr.sin6_addr)=%d:%d\n", ip,
            ret, errno);
  saddr.sin6_port = htons (atoi (port));

  ret = _connect (cfd, (struct sockaddr *) &saddr, sizeof (saddr));
  ERR_GOTO (ret < 0, CLEAN, "connect(%d, %s, %d)=%d:%d\n", cfd,
            f_in6addr (&saddr), len, ret, errno);
  out ("connect ok --> sleep(5)\n");
  sleep (5);

  ret = _send (cfd, buf, 10, 0);
  out ("send()=%d:%d --> sleep(5)\n", ret, errno);
  sleep (5);

  ret = _close (cfd);
  TEST_ASSERT (ret == 0);

  return ret;

CLEAN:
  (void) _close (cfd);
  return -1;
}

int
v4_tcp_server_shutdown_rd (int argc, const char *argv[])
{
  int sfd = -1, afd = -1, ret;
  struct sockaddr_in saddr = { 0 }, aaddr =
  {
  0};
  socklen_t len;
  const char *ip = argv[1];
  const char *port = argv[2];

  sfd = _socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
  ERR_RETURN (sfd < 0, sfd,
              "socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)=%d:%d\n", sfd,
              errno);

  saddr.sin_family = AF_INET;
  ret = inet_pton (AF_INET, ip, &saddr.sin_addr);
  ERR_GOTO (ret != 1, CLEAN_S,
            "inet_pton(AF_INET, ip=\"%s\", &saddr.sin_addr)=%d:%d\n", ip, ret,
            errno);
  saddr.sin_port = htons (atoi (port));

  ret = _bind (sfd, (struct sockaddr *) &saddr, sizeof (saddr));
  ERR_GOTO (ret < 0, CLEAN_S, "bind(%d, %s, %ld)=%d:%d\n", sfd,
            f_inaddr (&saddr), sizeof (saddr), ret, errno);

  ret = _listen (sfd, 100);
  ERR_GOTO (ret < 0, CLEAN_S, "listen(%d, 100)=%d:%d\n", sfd, ret, errno);

  len = sizeof (aaddr);
  afd = _accept (sfd, (struct sockaddr *) &aaddr, &len);
  ERR_GOTO (ret < 0, CLEAN_S, "accept(%d, %s, %d)=%d:%d\n", sfd,
            f_inaddr (&aaddr), len, ret, errno);

  out ("accept(sfd=%d, addr=%s, len=%d)=%d\n", sfd, f_inaddr (&aaddr), len,
       afd);
  sleep (2);

  ret = _shutdown (afd, SHUT_RD);
  ERR_GOTO (ret != 0, CLEAN, "shutdown(afd=%d, SHUT_RD)=%d:%d\n", afd, ret,
            errno);

  out ("shutdown(afd=%d, SHUT_RD) ok --> sleep(10)\n", afd);
  sleep (10);

  out ("closing\n");

  ret = _close (afd);
  TEST_ASSERT (ret == 0);

  ret = _close (sfd);
  TEST_ASSERT (ret == 0);

  return ret;

CLEAN:
  (void) _close (afd);
CLEAN_S:
  (void) _close (sfd);
  return -1;
}

int
v4_tcp_server_shutdown_wr (int argc, const char *argv[])
{
  int sfd = -1, afd = -1, ret;
  struct sockaddr_in saddr = { 0 }, aaddr =
  {
  0};
  socklen_t len;
  const char *ip = argv[1];
  const char *port = argv[2];

  sfd = _socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
  ERR_RETURN (sfd < 0, sfd,
              "socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)=%d:%d\n", sfd,
              errno);

  saddr.sin_family = AF_INET;
  ret = inet_pton (AF_INET, ip, &saddr.sin_addr);
  ERR_GOTO (ret != 1, CLEAN_S,
            "inet_pton(AF_INET, ip=\"%s\", &saddr.sin_addr)=%d:%d\n", ip, ret,
            errno);
  saddr.sin_port = htons (atoi (port));

  ret = _bind (sfd, (struct sockaddr *) &saddr, sizeof (saddr));
  ERR_GOTO (ret < 0, CLEAN_S, "bind(%d, %s, %ld)=%d:%d\n", sfd,
            f_inaddr (&saddr), sizeof (saddr), ret, errno);

  ret = _listen (sfd, 100);
  ERR_GOTO (ret < 0, CLEAN_S, "listen(%d, 100)=%d:%d\n", sfd, ret, errno);

  len = sizeof (aaddr);
  afd = _accept (sfd, (struct sockaddr *) &aaddr, &len);
  ERR_GOTO (ret < 0, CLEAN_S, "accept(%d, %s, %d)=%d:%d\n", sfd,
            f_inaddr (&aaddr), len, ret, errno);
  out ("accept(sfd=%d, addr=%s, len=%d)=%d\n", sfd, f_inaddr (&aaddr), len,
       afd);

  ret = _shutdown (afd, SHUT_WR);
  ERR_GOTO (ret != 0, CLEAN, "shutdown(afd=%d, SHUT_RD)=%d:%d\n", afd, ret,
            errno);
  out ("shutdown(afd=%d, SHUT_WR) ok --> sleep(10)\n", afd);
  sleep (10);

  out ("closing\n");

  ret = _close (afd);
  TEST_ASSERT (ret == 0);

  ret = _close (sfd);
  TEST_ASSERT (ret == 0);

  return ret;

CLEAN:
  (void) _close (afd);
CLEAN_S:
  (void) _close (sfd);
  return -1;
}

int
v4_tcp_client_s (int argc, const char *argv[])
{
  int cfd = -1, ret;
  struct sockaddr_in saddr = { 0 };
  socklen_t len;
  char buf[10] = { 'X', 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  const char *ip = argv[1];
  const char *port = argv[2];

  cfd = _socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
  ERR_RETURN (cfd < 0, cfd,
              "socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)=%d:%d\n", cfd,
              errno);

  saddr.sin_family = AF_INET;
  ret = inet_pton (AF_INET, ip, &saddr.sin_addr);
  ERR_GOTO (ret != 1, CLEAN,
            "inet_pton(AF_INET, ip=\"%s\", &saddr.sin_addr)=%d:%d\n", ip, ret,
            errno);
  saddr.sin_port = htons (atoi (port));

  ret = _connect (cfd, (struct sockaddr *) &saddr, sizeof (saddr));
  ERR_GOTO (ret < 0, CLEAN, "connect(%d, %s, %d)=%d:%d\n", cfd,
            f_inaddr (&saddr), len, ret, errno);
  out ("connect ok --> sleep(5)\n");
  sleep (5);

  ret = _send (cfd, buf, 10, 0);
  out ("send()=%d:%d --> sleep(5)\n", ret, errno);
  sleep (5);

  ret = _close (cfd);
  TEST_ASSERT (ret == 0);

  return ret;

CLEAN:
  (void) _close (cfd);
  return -1;
}

int
v6_tcp_server_close_select (int argc, const char *argv[])
{
  int sfd = -1, afd = -1, ret;
  struct sockaddr_in6 saddr = { 0 }, aaddr =
  {
  0};
  socklen_t len;
  const char *ip = argv[1];
  const char *port = argv[2];

  sfd = _socket (PF_INET6, SOCK_STREAM, IPPROTO_TCP);
  ERR_RETURN (sfd < 0, sfd,
              "socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)=%d:%d\n", sfd,
              errno);

  saddr.sin6_family = AF_INET6;
  ret = inet_pton (AF_INET6, ip, &saddr.sin6_addr);
  ERR_GOTO (ret != 1, CLEAN_S,
            "inet_pton(AF_INET6, ip=\"%s\", &saddr.sin6_addr)=%d:%d\n", ip,
            ret, errno);
  saddr.sin6_port = htons (atoi (port));

  ret = _bind (sfd, (struct sockaddr *) &saddr, sizeof (saddr));
  ERR_GOTO (ret < 0, CLEAN_S, "bind(%d, %s, %ld)=%d:%d\n", sfd,
            f_in6addr (&saddr), sizeof (saddr), ret, errno);

  ret = _listen (sfd, 100);
  ERR_GOTO (ret < 0, CLEAN_S, "listen(%d, 100)=%d:%d\n", sfd, ret, errno);

  len = sizeof (aaddr);
  afd = _accept (sfd, (struct sockaddr *) &aaddr, &len);
  ERR_GOTO (ret < 0, CLEAN_S, "accept(%d, %s, %d)=%d:%d\n", sfd,
            f_in6addr (&aaddr), len, ret, errno);

  out ("accept(sfd=%d, addr=%s, len=%d)=%d\n", sfd, f_in6addr (&aaddr), len,
       afd);

  ret = _close (afd);
  ERR_GOTO (ret != 0, CLEAN_S, "close(afd=%d)=%d:%d\n", afd, ret, errno);
  out ("close(afd=%d) ok --> sleep(2)\n", afd);
  sleep (2);

  {
    fd_set rfds, wfds, efds;
    int nfds = afd + 1;
    FD_ZERO (&rfds);
    FD_SET (afd, &rfds);
    FD_ZERO (&wfds);
    FD_SET (afd, &wfds);
    FD_ZERO (&efds);
    FD_SET (afd, &efds);
    ret = select (nfds, &rfds, &wfds, &efds, NULL);
    int err = errno;
    TEST_ASSERT (ret == -1);
    TEST_ASSERT (err == EBADF);
  }

  ret = _close (sfd);
  TEST_ASSERT (ret == 0);

  return ret;

CLEAN:
  (void) _close (afd);
CLEAN_S:
  (void) _close (sfd);
  return -1;
}

struct config
{
  char opt;
  const char *name;
  const char *help;
  int (*proc) (int argc, const char *argv[]);
};

struct config list[] = {
  {'l', "v6_tcp_server_listen", "X::X PORT", v6_tcp_server_listen},
  {'L', "v6_tcp_server_listen", "X::X PORT", v6_tcp_server_listen},
  {'-', NULL, NULL, NULL},
  {'c', "v6_tcp_client_s", "X::X PORT", v6_tcp_client_s},
  {'s', "v6_tcp_server_shutdown_rd", "X::X PORT", v6_tcp_server_shutdown_rd},
  {'d', "v6_tcp_server_shutdown_wr", "X::X PORT", v6_tcp_server_shutdown_wr},
  {'f', "v6_tcp_server_shutdown_rdwr", "X::X PORT",
   v6_tcp_server_shutdown_rdwr},
  {'-', NULL, NULL, NULL},
  {'1', "v4_tcp_client_s", "X.X.X.X PORT", v4_tcp_client_s},
  {'2', "v4_tcp_server_shutdown_rd", "X.X.X.X PORT",
   v4_tcp_server_shutdown_rd},
  {'3', "v4_tcp_server_shutdown_wr", "X.X.X.X PORT",
   v4_tcp_server_shutdown_wr},
  {'-', NULL, NULL, NULL},
  {'U', "test_v6_udp", "X::X", test_v6_udp},
  {'u', "test_v4_udp", "X.X.X.X", test_v4_udp},
  {'t', "test_v4_tcp", "X.X.X.X", test_v4_tcp},
  {'-', NULL, NULL, NULL},
  {'b', "v6_udp_close_select", "X::X PORT", v6_udp_close_select},
};

int
usage ()
{
  int i;
  for (i = 0; i < sizeof (list) / sizeof (list[0]); ++i)
    {
      if (list[i].opt == '-')
        out ("\n");
      else
        out ("%c : %s ( %s )\n", list[i].opt, list[i].name, list[i].help);
    }
  return 0;
}

int
main (int argc, const char *argv[])
{
  int i, ret;

  argc--;
  argv++;

  if (argc <= 0)
    return usage ();

  for (i = 0; i < sizeof (list) / sizeof (list[0]); ++i)
    {
      if (list[i].opt == '-')
        continue;
      if (argv[0][0] != list[i].opt)
        continue;

      out ("Test %s%s%s begin\n", CH, list[i].name, CC);
      ret = list[i].proc (argc, argv);
      if (ret)
        out ("%sFAILED%s: %s\n", FR__, CC, list[i].name);
      else
        out ("OK: %s\n", list[i].name);

      out ("\n <<<< over <<<<\n");
      return 0;
    }

  return usage ();
}
