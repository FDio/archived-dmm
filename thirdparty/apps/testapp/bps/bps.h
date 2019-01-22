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

#ifndef _BPS_H_
#define _BPS_H_

#define BPS_EXCH_DELAY 10       /* ms */
#define BPS_STAT_TIMER 49       /* ms */

#define BPS_MAX_PARALLEL 128
#define BPS_MAX_SESS 1024

#define BPS_MAX_LEN (1 * 1024)

#define BPS_DEF_PORT 58177
#define BPS_DEF_LEN 458
#define BPS_DEF_PARALLEL 1
#define BPS_DEF_TIME 30
#define BPS_DEF_REPORT_TIME 1

#define BPS_IO_SEND 0x1
#define BPS_IO_RECV 0x2

#define BPS_BREAK	(-1)
#define BPS_RUNNING 0
#define BPS_STOP	1

#define BPS_ERROR	64
#define BPS_SEND_ERROR (BPS_ERROR | 1)
#define BPS_RECV_ERROR (BPS_ERROR | 2)

struct bps_rec
{
  uint64_t rcv;
  uint64_t snd;
};

struct bps_sess_head
{
  struct bps_sess *next;
  struct bps_sess *prev;
};

struct bps_sess
{
  struct bps_sess_head head;    //must be first

  int fd;
  uint16_t index;
  volatile short state;

  int recv_core;
  int send_core;
  pthread_t recv_tid;
  pthread_t send_tid;
};

struct bps_var
{
  /* begin config */
  int verbose;
  int exact;
  int client_mode;
  int client_bind;

  int io_mode;
  int parallel;
  int buf_size;
  int msg_len;

  uint64_t bind_core;
  int report_time;
  int test_time;
  struct sockaddr_in bind_addr;
  struct sockaddr_in server_addr;

  /* end config */

  uint16_t global_index;
  short state;
  int listen_fd;

  struct bps_rec rec_list[2][BPS_MAX_SESS];
  struct bps_rec *rec_now;

  struct timespec begin_time;
  struct timespec last_time;
  struct timespec next_time;

  struct bps_sess sess_list[BPS_MAX_SESS];
  struct bps_sess *free_sess;
  struct bps_sess_head sess_head;
  int sess_num;
  int max_sess_id;
};

#define BPS_SESS_ID(sess) ((sess) - &bps.sess_list[0])

#endif /* #ifndef _BPS_H_ */
