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

#ifndef _API_H_
#define _API_H_

#if defined(NSOCKET)
#define VERSION_NAME "NSTACK"
#define _socket		nstack_socket
#define _fcntl			nstack_fcntl
#define _bind			nstack_bind
#define _listen		nstack_listen
#define _accept		nstack_accept
#define _accept4		nstack_accept4
#define _connect 		nstack_connect
#define _close 		nstack_close
#define _shutdown 		nstack_shutdown
#define _recv 			nstack_recv
#define _send 			nstack_send
#define _getsockname	nstack_getsockname
#define _getpeername	nstack_getpeername
#define _getsockopt	nstack_getsockopt
#define _setsockopt	nstack_setsockopt
#define _recvfrom 		nstack_recvfrom
#define _sendto		nstack_sendto
#define _read 			nstack_read
#define _write			nstack_write
#define _epoll_create	nstack_epoll_create
#define _epoll_ctl		nstack_epoll_ctl
#define _epoll_wait	nstack_epoll_wait
#elif defined(LWIP)
#define VERSION_NAME "LWIP"
#define _socket		lwip_socket
#define _fcntl			lwip_fcntl
#define _bind			lwip_bind
#define _listen		lwip_listen
#define _accept		lwip_accept
#define _accept4		lwip_accept4
#define _connect 		lwip_connect
#define _close 		lwip_close
#define _shutdown 		lwip_shutdown
#define _recv 			lwip_recv
#define _send 			lwip_send
#define _getsockname	lwip_getsockname
#define _getpeername	lwip_getpeername
#define _getsockopt	lwip_getsockopt
#define _setsockopt	lwip_setsockopt
#define _recvfrom 		lwip_recvfrom
#define _sendto		lwip_sendto
#define _read 			lwip_read
#define _write			lwip_write
#define _epoll_create	lwip_epoll_create
#define _epoll_ctl		lwip_epoll_ctl
#define _epoll_wait	lwip_epoll_wait
#else
#define VERSION_NAME "POSIX"
#define _socket		socket
#define _fcntl			fcntl
#define _bind			bind
#define _listen		listen
#define _accept		accept
#define _accept4		accept4
#define _connect 		connect
#define _close 		close
#define _shutdown 		shutdown
#define _recv 			recv
#define _send 			send
#define _getsockname	getsockname
#define _getpeername	getpeername
#define _getsockopt	getsockopt
#define _setsockopt	setsockopt
#define _recvfrom 		recvfrom
#define _sendto		sendto
#define _read 			read
#define _write			write
#define _epoll_create	epoll_create
#define _epoll_ctl		epoll_ctl
#define _epoll_wait	epoll_wait
#endif

#endif /* #ifndef _API_H_ */

#ifndef SOCKET_WARP_LB_H_
#define SOCKET_WARP_LB_H_

inline static int
set_nonblock_v (int fd, int nonblock)
{
  int fl = _fcntl (fd, F_GETFL, 0);

  if (fl < 0)
    return fl;

  if (nonblock)
    {
      if (fl & O_NONBLOCK)
        return 0;
      fl |= O_NONBLOCK;
    }
  else
    {
      if (0 == (fl & O_NONBLOCK))
        return 0;
      fl &= ~(O_NONBLOCK);
    }

  return _fcntl (fd, F_SETFL, fl | O_NONBLOCK);
}

inline static int
set_nonblock (int fd)
{
  int fl = _fcntl (fd, F_GETFL, 0);
  if (fl < 0)
    return fl;
  return _fcntl (fd, F_SETFL, fl | O_NONBLOCK);
}

inline static int
set_nodelay (int fd, int nodelay)
{
  return _setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, (void *) &nodelay,
                      sizeof (nodelay));
}

inline static int
set_rcvtimeo (int fd, int us)
{
  struct timeval timeout = {.tv_sec = us / USOFS,.tv_usec = us % USOFS };
  return _setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof (timeout));
}

inline static int
set_reuseaddr (int fd, int reuseaddr)
{
  return _setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (char *) &reuseaddr,
                      sizeof (reuseaddr));
}

inline static int
set_reuseport (int fd, int reuseport)
{
  return _setsockopt (fd, SOL_SOCKET, SO_REUSEPORT, (char *) &reuseport,
                      sizeof (reuseport));
}

inline static int
set_sndtimeo (int fd, int us)
{
  struct timeval timeout = {.tv_sec = us / USOFS,.tv_usec = us % USOFS };
  return _setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                      sizeof (timeout));
}

#endif /* #ifndef SOCKET_WARP_LB_H_ */
