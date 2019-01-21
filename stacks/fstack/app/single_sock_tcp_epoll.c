#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <sys/epoll.h>
#include "dmm_pub_api.h"
#include <pthread.h>
#include <fcntl.h>

#define MAX_EVENTS 512

int gepfd;
int fstack_listen_fd, i, readlen;
char buffer[1024] = { 0 };

char fstack_html[] =
  "HTTP/1.1 200 OK\r\n"
  "Server: F-Stack\r\n"
  "Date: Sat, 25 Feb 2017 09:26:33 GMT\r\n"
  "Content-Type: text/html\r\n"
  "Content-Length: 439\r\n"
  "Last-Modified: Tue, 21 Feb 2017 09:44:03 GMT\r\n"
  "Connection: keep-alive\r\n"
  "Accept-Ranges: bytes\r\n"
  "\r\n"
  "<!DOCTYPE html>\r\n"
  "<html>\r\n"
  "<head>\r\n"
  "<title>Welcome to F-Stack!</title>\r\n"
  "<style>\r\n"
  "    body {  \r\n"
  "        width: 35em;\r\n"
  "        margin: 0 auto; \r\n"
  "        font-family: Tahoma, Verdana, Arial, sans-serif;\r\n"
  "    }\r\n"
  "</style>\r\n"
  "</head>\r\n"
  "<body>\r\n"
  "<h1>Welcome to F-Stack!</h1>\r\n"
  "\r\n"
  "<p>For online documentation and support please refer to\r\n"
  "<a href=\"http://F-Stack.org/\">F-Stack.org</a>.<br/>\r\n"
  "\r\n"
  "<p><em>Thank you for using F-Stack.</em></p>\r\n" "</body>\r\n" "</html>";
struct epoll_event ev;
struct epoll_event events[MAX_EVENTS];

static struct sockaddr_in g_f_ser;

static void
setArgsDefault ()
{
  memset (&g_f_ser, 0, sizeof (g_f_ser));
  g_f_ser.sin_family = AF_INET;
  g_f_ser.sin_addr.s_addr = inet_addr ("0.0.0.0");
  g_f_ser.sin_port = htons (80);
  bzero (&(g_f_ser.sin_zero), 8);
}

static int
process_arg (int argc, char *argv[])
{
  int opt = 0;
  const char *optstring = "f:";

  if (argc < 1)
    {
      printf ("Param info :-f fstack server address;\n");
      return 0;
    }
  while ((opt = getopt (argc, argv, optstring)) != -1)
    {
      switch (opt)
        {
        case 'f':
          g_f_ser.sin_addr.s_addr = inet_addr (optarg);
          break;
        }
    }
  return 1;
}

void
clear_fd (int clearFd)
{
  epoll_ctl (gepfd, EPOLL_CTL_DEL, clearFd, NULL);
  close (clearFd);
  printf ("%d fd has been deleted from the epoll list\n\n\n", clearFd);
}

int
loop (void *arg)
{
  /* Wait for events to happen */
  (void) nstack_epoll_prewait ();
  int nevents = epoll_wait (gepfd, events, MAX_EVENTS, 0);

  for (i = 0; i < nevents; ++i)
    {
      /* Handle new connect */
      if (events[i].data.fd == fstack_listen_fd)
        {
          while (1)
            {
              int fstack_accept_fd = accept (events[i].data.fd, NULL, NULL);
              if (fstack_accept_fd < 0)
                {
                  break;
                }

              printf ("f-stack listen fd = %d f-stack accept fd = %d\n",
                      fstack_listen_fd, fstack_accept_fd);

              ev.data.fd = fstack_accept_fd;
              ev.events = EPOLLIN;

              /* Add to event list */
              if (epoll_ctl (gepfd, EPOLL_CTL_ADD, fstack_accept_fd, &ev) !=
                  0)
                {
                  printf ("epoll_ctl failed:%d, %s\n", errno,
                          strerror (errno));
                  break;
                }
            }
        }
      else
        {
          if (events[i].events & EPOLLERR)
            {
              /* Simply close socket */
              clear_fd (events[i].data.fd);
            }
          else if (events[i].events & EPOLLIN)
            {
              readlen = recv (events[i].data.fd, buffer, sizeof (buffer), 0);
              printf ("read event on fd = %d readlen %d\n", events[i].data.fd,
                      readlen);
              if (readlen > 0)
                {
                  printf ("received below buffer from client\n %s\n", buffer);
                  if (sizeof (fstack_html) !=
                      send (events[i].data.fd, fstack_html,
                            sizeof (fstack_html), 0))
                    {
                      printf ("fstack send failed\n");
                    }
                  printf ("fstack send fd = %d\n", events[i].data.fd);
                }
              else
                {
                  clear_fd (events[i].data.fd);
                }
            }
          else
            {
              printf ("unknown event: %8.8X\n", events[i].events);
            }
        }
    }
}

void
main (int argc, char *argv[])
{
  int on = 1, ret = 0;

  setArgsDefault ();
  ret = process_arg (argc, argv);
  if (ret != 1)
    {
      printf ("The param error\n");
      return;
    }

  /* fstack */
  fstack_listen_fd = socket (AF_INET, SOCK_STREAM, 0);
  printf ("sockfd:%d\n", fstack_listen_fd);
  if (fstack_listen_fd < 0)
    {
      printf ("socket failed\n");
      exit (1);
    }

  ioctl (fstack_listen_fd, FIONBIO, &on);

  ret =
    bind (fstack_listen_fd, (struct sockaddr *) &g_f_ser, sizeof (g_f_ser));
  if (ret < 0)
    {
      printf ("bind failed\n");
      exit (1);
    }

  ret = listen (fstack_listen_fd, MAX_EVENTS);
  if (ret < 0)
    {
      printf ("listen failed\n");
      exit (1);
    }

  assert ((gepfd = epoll_create (100)) > 0);
  ev.data.fd = fstack_listen_fd;
  ev.events = EPOLLIN;
  epoll_ctl (gepfd, EPOLL_CTL_ADD, fstack_listen_fd, &ev);
  nstack_run ((void *) loop);
  return;
}
