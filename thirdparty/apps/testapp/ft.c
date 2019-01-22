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

int fd = -1;

void *
thread (void *arg)
{
  struct epoll_event ev[32];
  int id = *(int *) arg;
  int ep = _epoll_create (1);
  int i, num;

  ev[0].events = EPOLLIN | EPOLLET;
  ev[0].data.fd = id;
  _epoll_ctl (ep, EPOLL_CTL_ADD, fd, &ev[0]);

  while (1)
    {
      num = _epoll_wait (ep, ev, 32, -1);

      (void) printf ("thread %d recv events %d\n", id, num);

      for (i = 0; i < num; ++i)
        {
          (void)
            printf
            ("thread %d recv events %d : index: %d id: %d event: 0x%x\n", id,
             num, i, ev[i].data.fd, ev[i].events);
        }
    }

  return NULL;
}

int
main (int argc, const char *argv[])
{
  struct sockaddr_in addr = { 0 };
  int id1 = 1, id2 = 2, id3 = 3;

  fd = _socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0)
    return 1;

  addr.sin_family = AF_INET;
  addr.sin_port = htons (10000);

  _bind (fd, (struct sockaddr *) &addr, sizeof (addr));
  _listen (fd, 10);

  pthread_t t1 = lb_thread (thread, (void *) &id1, "thread-1");
  pthread_t t2 = lb_thread (thread, (void *) &id2, "thread-2");
  pthread_t t3 = lb_thread (thread, (void *) &id3, "thread-3");

  sleep (1000000);

  return 0;
}
