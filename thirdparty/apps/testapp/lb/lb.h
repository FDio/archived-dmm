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

#ifndef _LB_H_
#define _LB_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <sched.h>
#include <getopt.h>
#include <execinfo.h>
#include <linux/futex.h>

#define KB 1000
#define MB (1000 * KB)
#define GB (1000 * MB)
#define TB (1000 * GB)

#define MSOFS	(1000)
#define USOFS	(1000 * 1000)
#define NSOFS	(1000 * 1000 * 1000)
#define NSOFMS 	(1000 * 1000)

#define NOINLINE __attribute__((noinline))
#define no_inline __attribute__((noinline))

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#include "api.h"

#define out(fmt, arg...) (void)printf(fmt, ##arg)

#define info(fmt, arg...) (void)printf("%s[I:%d]%s " fmt, CR, __LINE__, CC, ##arg)
#define wrn(fmt, arg...) (void)printf("%s[W:%d]%s " fmt, FR__, __LINE__, CC, ##arg)
#define err(fmt, arg...) (void)fprintf(stderr, "%s[E:%d]%s " fmt, BR__, __LINE__, CC, ##arg)

#define WRN(cond, fmt, arg...) do { if (cond) wrn(fmt, ##arg); } while (0)

#define ERR_RETURN(cond, ret, fmt, arg...) do { \
	if (cond) { \
		if (fmt) err(fmt, ##arg); \
		return ret; \
	} \
} while(0)

#define ERR_GOTO(cond, TO, fmt, arg...) do { \
	if (cond) { \
		if (fmt) err(fmt, ##arg); \
		goto TO; \
	} \
} while (0)

#define DBGOPT "D"
#define DBGOPT_LONG {"debug", 0, 0, 'D'},

extern int enable_debug;

#define DBG(fmt, arg...) do { \
	if (enable_debug) \
		out("[D:%d]%s " fmt, __LINE__, __func__, ##arg); \
} while (0)

#define T DBG("\n");

#define CNT_OF(a) (sizeof(a) / sizeof(a[0]))

#define OFF_OF(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define CON_OF(ptr, type, member) ({					\
	const typeof( ((type*)0)->member ) *__mptr = (ptr); \
	(type*)( (char*)__mptr - OFF_OF(type, member) ); \
})
#define NUM_OF(a) (sizeof((a)) / sizeof((a)[0]))

#if 1
#define TIMEPOINT

#define TP(name) struct timespec _tp_##name; \
		(void)clock_gettime(CLOCK_MONOTONIC, &_tp_##name)
#define TO(from, to) do { \
		struct timespec _t; \
		LB_SUB_TS(_tp_##to, _tp_##from, _t); \
		out("@TP>%s:%d:%s %lu.%09lu %s-%s\n", __FILE__, __LINE__, __func__, \
			_t.tv_sec, _t.tv_nsec, #from, #to); \
} while (0)
#define TN(from, to, NUM) do { \
	static uint64_t _n = 0; \
	static struct timespec _t = {0}; \
	_t.tv_nsec += (_tp_##to.tv_nsec - _tp_##from.tv_nsec); \
	_t.tv_sec += (_tp_##to.tv_sec - _tp_##from.tv_sec); \
	if (++_n >= NUM) { \
		uint64_t _nsec = _t.tv_sec * 1000000000ul + _t.tv_nsec; \
		_nsec /= _n; \
		out("@TP<%lu>%s:%d:%s %lu.%09lu %s-%s\n", _n, __FILE__, __LINE__, __func__, \
			_nsec/1000000000ul, _nsec%1000000000ul, #from, #to); \
		_t.tv_sec = 0; \
		_t.tv_nsec = 0; \
		_n = 0; \
	} \
} while (0)
#else

#define TP(name) ((void)0)
#define TO(from, to) ((void)0)
#define TN(from, to, NUM) ((void)0)

#endif

#define TQ(name) do { TP(__); TO(name, __); } while (0)
#define TM(name, NUM) do { TP(__); TN(name, __, NUM); } while (0)

#define TO1(n1,n2) TO(n1,n2)
#define TO2(n1,n2,n3) do { TO(n1,n2); TO1(n2,n3); } while(0)
#define TO3(n1,n2,n3...) do { TO(n1,n2); TO2(n2,n3); } while(0)
#define TO4(n1,n2,n3...) do { TO(n1,n2); TO3(n2,n3); } while(0)
#define TO5(n1,n2,n3...) do { TO(n1,n2); TO4(n2,n3); } while(0)
#define TO6(n1,n2,n3...) do { TO(n1,n2); TO5(n2,n3); } while(0)

#define TE(N,n...) do { TP(__); TO##N(n, __);} while (0)

#define tp1 TP(1)
#define tq1 TQ(1)
#define tp2 TP(2)
#define tq2 TQ(2)
#define tp3 TP(3)
#define tq3 TQ(3)
#define tp4 TP(4)
#define tq4 TQ(4)
#define tp5 TP(5)
#define tq5 TQ(5)

#ifndef COLOR_LB_H_
#define COLOR_LB_H_

struct lb_color
{
  const char *clear;
  const char *high;
  const char *uline;
  const char *flash;
  const char *rev;

  const char *fblack;
  const char *fr__;
  const char *f_g_;
  const char *f__b;
  const char *frg_;
  const char *fr_b;
  const char *f_gb;
  const char *fwhite;

  const char *bblack;
  const char *br__;
  const char *b_g_;
  const char *b__b;
  const char *brg_;
  const char *br_b;
  const char *b_gb;
  const char *bwhite;
};

enum
{
  LB_DEF_COLOR = 0,
  LB_NO_COLOR = 1,
};

extern const struct lb_color *lb_color;
extern int lb_color_index;
void lb_set_color (int index);

#define CC lb_color->clear
#define CR lb_color->rev
#define CH lb_color->high
#define CU lb_color->uline
#define CF lb_color->flash

#define FBLACK lb_color->fblack
#define FR__   lb_color->fr__
#define F_G_   lb_color->f_g_
#define F__B   lb_color->f__b
#define FRG_   lb_color->frg_
#define FR_B   lb_color->fr_b
#define F_GB   lb_color->f_gb
#define FWHITE lb_color->fwhite

#define BBLACK lb_color->bblack
#define BR__   lb_color->br__
#define B_G_   lb_color->b_g_
#define B__B   lb_color->b__b
#define BRG_   lb_color->brg_
#define BR_B   lb_color->br_b
#define B_GB   lb_color->b_gb
#define BWHITE lb_color->bwhite

#endif

#ifndef TIME_LB_H_
#define TIME_LB_H_

#define LB_RAND(num) ((int) ((random() / (RAND_MAX + 1.0)) * num))

#define LB_TIME(now) (void)clock_gettime(CLOCK_MONOTONIC, &(now))
#define LB_REALTIME(now) (void)clock_gettime(CLOCK_REALTIME, &(now))

#define LB_SUB_OS(end, begin) ((end).tv_sec - (begin).tv_sec)
#define LB_SUB_NS(end, begin) (((end).tv_sec - (begin).tv_sec) * NSOFS + (end).tv_nsec - (begin).tv_nsec)

#define LB_SUB_TS(end, begin, out) ({ \
	if ((end).tv_nsec >= (begin).tv_nsec) { \
		(out).tv_nsec = (end).tv_nsec - (begin).tv_nsec; \
		(out).tv_sec = (end).tv_sec - (begin).tv_sec; \
	} else { \
		(out).tv_nsec = (end).tv_nsec + NSOFS - (begin).tv_nsec; \
		(out).tv_sec = (end).tv_sec - (begin).tv_sec - 1; \
	} \
})

#define LB_CMP(end, begin) ((end).tv_sec > (begin).tv_sec ? 1 : ( \
		(end).tv_sec < (begin).tv_sec ? -1 : (end).tv_nsec - (begin).tv_nsec))

#define LB_CMP_SN(end, begin, sec, nsec) ({ \
	time_t _s = (end).tv_sec - (begin).tv_sec; \
	(_s > (sec)) || (_s == (sec) && (end).tv_nsec - (begin).tv_nsec >= (nsec)); \
})

#define LB_CMP_TS(end, begin, ts) LB_CMP_SN((end), (begin), (ts).tv_sec, (ts).tv_nsec)
#define LB_CMP_S(end, begin, sec) LB_CMP_SN((end), (begin), (sec), 0)
#define LB_CMP_NS(end, begin, nsec) LB_CMP_SN((end), (begin), 0, (nsec))

#endif /* #ifndef TIME_LB_H_ */

#ifndef MATH_LB_H_
#define MATH_LB_H_

/* return a * 10^9 / b */
inline static uint64_t
lb_gdiv (uint64_t a, uint64_t b)
{
  const uint64_t M = 0xFFFFffffFFFFfffful;
  const uint64_t N = 1000 * 1000 * 1000;
  const uint64_t P = 1000;

  uint64_t r;

  if (b == 0)
    b = 1;

  if (a <= M / N)
    return a * N / b;

  r = a / b;

  a = a % b * P;
  r = r * P + a / b;

  a = a % b * P;
  r = r * P + a / b;

  a = a % b * P;
  r = r * P + a / b;

  return r;
}

inline static uint64_t
lb_sdiv (uint64_t a, uint64_t b)
{
  if (b)
    return a / b;
  return 0;
}

#endif /* #ifndef MATH_LB_H_ */
#ifndef RUN_LB_H_
#define RUN_LB_H_

struct lb_slot
{
  struct timespec begin;
  uint64_t count;
};

struct lb_run
{
  uint32_t index;
  uint32_t mask;
  uint32_t rate;
  uint32_t time;
  uint64_t total;
  struct lb_slot slot[0];
};

/* num:1 << N;	time: ns */
inline static void
run_init (struct lb_run *run, uint32_t rate, uint32_t num, uint32_t time)
{
  int i;
  struct lb_slot *slot = run->slot;
  struct timespec begin;

  LB_TIME (begin);

  run->index = 0;
  run->mask = num - 1;
  run->rate = rate;
  run->time = time;
  run->total = 0;

  for (i = 0; i < num; ++i, ++slot)
    {
      slot->begin = begin;
      slot->count = 0;
    }
}

/* return: the number should add for run to now */
inline static int64_t
run_test (struct lb_run *run, struct timespec *now)
{
  uint64_t time, num;
  struct lb_slot *slot = run->slot;
  struct lb_slot *cur = slot + (run->index & run->mask);

  if (LB_CMP_NS (*now, cur->begin, run->time))
    {
      cur = slot + ((++run->index) & run->mask);
      run->total -= cur->count;
      cur->count = 0;
      cur->begin = *now;
    }

  slot += ((run->index + 1) & run->mask);
  time = LB_SUB_NS (*now, slot->begin);
  num = time * run->rate;

  if ((num % NSOFS) >= (NSOFS / 2))
    return num / NSOFS - run->total + 1;
  return num / NSOFS - run->total;
}

inline static int
run_add (struct lb_run *run, int64_t num)
{
  run->total += num;
  run->slot[run->index & run->mask].count += num;
}

#endif

#ifndef FORMAT_LB_H_
#define FORMAT_LB_H_

const char *f_in6 (const struct in6_addr *ip6);
const char *f_in6addr (const struct sockaddr_in6 *addr);
const char *f_inaddr (const struct sockaddr_in *addr);
const char *f_uint (uint64_t val);
int s_uint (char *buf, uint64_t val);
int r_uint (char *buf, uint64_t val, int size);

#endif

#ifndef PARSE_LB_H_
#define PARSE_LB_H_

uint64_t p_hex (const char *arg, const char **end);
uint64_t p_uint (const char *arg, uint64_t max, const char **end);
inline static long
p_int (const char *arg, long max, const char **end)
{
  return (long) (unsigned long) p_uint (arg, (uint64_t) (unsigned long) max,
                                        end);
}

struct inaddrs
{
  uint32_t ip;
#if 0
  uint32_t ip_num;
  uint32_t ip_step;
#else
  int ip_num;
#endif
  uint16_t port;
  uint16_t port_num;
};

uint32_t p_ip (const char **arg);
int p_addr (const char *str, struct sockaddr_in *addr);
const char *p_addr_set (const char *arg, struct inaddrs *addr, uint32_t flag);
int p_addr_list (const char *arg, struct inaddrs *list, int num,
                 uint32_t flag, const char **end);
int addr_total (const struct inaddrs *list, int num, uint32_t mode);
int addr_layout (const struct inaddrs *list, int list_num,
                 struct sockaddr_in *addr, int addr_num, uint32_t mode);
inline static int
p_addrin_list (const char *arg, struct sockaddr_in **addr, int max,
               uint32_t flag, const char **end)
{
  int num, total;
  struct inaddrs list[max];
  struct sockaddr_in *out;

  num = p_addr_list (arg, list, max, flag, end);
  if (num <= 0)
    return -1;

  total = addr_total (list, num, flag);
  if (total > max)
    return -1;

  out = (struct sockaddr_in *) malloc (sizeof (struct sockaddr_in) * total);
  if (!out)
    return -1;

  num = addr_layout (list, num, out, total, flag);

  if (num != total)
    {
      free (out);
      return -1;
    }

  *addr = out;
  return num;
}

#define PA_DEFPORT_MASK 0x0000FFFF

#define PA_NO_TO_IP		0x00010000
#define PA_NO_NUM_IP 	0x00020000
#define PA_MAY_INV_IP	0x00040000
#define PA_MULTI_ONE	0x00080000

#define PA_NO_TO_PORT	0x00100000
#define PA_NO_NUM_PORT 	0x00200000
#define PA_NO_PORT		0x00400000
#define PA_MUST_PORT	0x00800000
#define PA_DEF_PORT		0x00C00000

#define PA_NO_TO_ALL	(PA_NO_TO_IP | PA_NO_TO_PORT)
#define PA_NO_NUM_ALL	(PA_NO_NUM_IP | PA_NO_NUM_PORT)
#define PA_SINGLE_IP	(PA_NO_TO_IP | PA_NO_NUM_IP)
#define PA_SINGLE_PORT	(PA_NO_TO_PORT | PA_NO_NUM_PORT)

#define PAL_NO_SPACE	0x10000000
#define PAL_WITH_NL		0x20000000
//#define PAL_SC_SPLIT    0x40000000

#define PAL_CROSS_MASK	0x03000000
#define PAL_IP_X_PORT	0x00000000
#define PAL_INC_BOTH	0x01000000
#define PAL_PORT_X_IP	0x02000000

const char *p_ip6 (const char *pos, struct in6_addr *ip);
inline static int
inet6_aton (const char *cp, struct in6_addr *addr)
{
  cp = p_ip6 (cp, addr);
  if (!cp || cp[0] != 0)
    return 0;
  return 1;
}

int p_addr6 (const char *arg, struct sockaddr_in6 *addr);

#endif

#ifndef UNIT_LB_H_
#define UNIT_LB_H_

enum unit_type
{
  UNIT_1,

  UNIT_k,
  UNIT_m,
  UNIT_g,
  UNIT_w,

  UNIT_K,
  UNIT_M,
  UNIT_G,

  UNIT_hour,
  UNIT_min,
  UNIT_sec,

  UNIT_1n,
  UNIT_hn,
  UNIT_mn,
  UNIT_sn,
  UNIT_ms,
  UNIT_us,
  UNIT_ns,

  UNIT_PC,

  UNIT_NUM,

  UB_1 = 1 << UNIT_1,

  UB_k = 1 << UNIT_k,
  UB_m = 1 << UNIT_m,
  UB_g = 1 << UNIT_g,
  UB_w = 1 << UNIT_w,

  UB_K = 1 << UNIT_K,
  UB_M = 1 << UNIT_M,
  UB_G = 1 << UNIT_G,

  UB_hour = 1 << UNIT_hour,
  UB_min = 1 << UNIT_min,
  UB_sec = 1 << UNIT_sec,

  UB_hn = 1 << UNIT_hn,
  UB_mn = 1 << UNIT_mn,
  UB_sn = 1 << UNIT_sn,
  UB_1n = 1 << UNIT_1n,
  UB_ms = 1 << UNIT_ms,
  UB_us = 1 << UNIT_us,
  UB_ns = 1 << UNIT_ns,

  UB_PC = 1 << UNIT_PC,

  UB_T1U_MASK = 3 << UNIT_NUM,
  UB_T1U_ns = 0 << UNIT_NUM,
  UB_T1U_us = 1 << UNIT_NUM,
  UB_T1U_ms = 2 << UNIT_NUM,
  UB_T1U_s = 3 << UNIT_NUM,

  UB_kmgw = UB_k | UB_m | UB_g | UB_w,
  UB_KMG = UB_K | UB_M | UB_G,
  UB_1kmgwKMG = UB_1 | UB_kmgw | UB_KMG,

  UB_smun = UB_sn | UB_ms | UB_us | UB_ns,
  UB_hms1 = UB_hour | UB_min | UB_sec | UB_1,

};

int p_unit (const char **arg, int mask, uint64_t * unit);

inline static uint64_t
p_value (const char *arg, uint64_t max, int mask, const char **end)
{
  uint64_t val = p_uint (arg, max, &arg);

  if (arg)
    {
      uint64_t unit;
      if (p_unit (&arg, mask, &unit) >= 0)
        {
          val *= unit;
          if (val <= max)
            {
              if (end)
                *end = arg;
              return val;
            }
        }
    }

  if (end)
    *end = NULL;
  return 0;
}

#endif

#ifndef CACHED_OUTPUT_LB_H_
#define CACHED_OUTPUT_LB_H_

typedef uint16_t cosize_t;

struct cohead
{
  cosize_t size;
  cosize_t free;
};

#define CO_OUT(head) stdout
#define CO_INIT(buf) co_init(buf, sizeof(buf))

inline static void
co_init (char buf[], cosize_t size)
{
  struct cohead *head = (struct cohead *) buf;
  head->size = size - sizeof (struct cohead);
  head->free = head->size;
  buf[sizeof (struct cohead)] = 0;
}

inline static void
_co_flush (struct cohead *head)
{
  char *buf = (char *) (head + 1);
  (void) fputs (buf, CO_OUT (head));
  head->free = head->size;
  *buf = 0;
}

inline static void
co_flush (char buf[])
{
  struct cohead *head = (struct cohead *) buf;
  if (head->free != head->size)
    _co_flush (head);
}

int co_wr_uint (char buf[], uint64_t val, int wide);

int co_app_ch (char buf[], char ch);
#define co_ch_if(cond, buf, ch) ( \
	(!!(cond)) ? co_app_ch((buf), (ch)) : 0)

int co_append (char buf[], cosize_t max, const char *fmt, ...)
  __attribute__ ((__format__ (__printf__, 3, 4)));
#define co_app_if(cond, buf, max, fmt, arg...) ( \
	(!!(cond)) ? co_append((buf), (max), (fmt), ##arg) : 0)
#define co_app_fls(buf, max, fmt, arg...) do { \
	co_append(buf, max, fmt, ##arg); \
	co_flush(); \
} while (0)

#endif

#ifndef SYSTEM_LB_H_
#define SYSTEM_LB_H_

inline static void
futex_wait (volatile int *addr, int val)
{
  while (*addr == val)
    {
      (void) syscall (SYS_futex, addr, FUTEX_WAIT, val, NULL, NULL, 0);
    }
}

inline static void
futex_wake (volatile int *addr, int num)
{
  (void) syscall (SYS_futex, addr, FUTEX_WAKE, num, NULL, NULL, 0);
}

pthread_t lb_thread (void *(*proc) (void *), void *arg, const char *fmt, ...);

inline static int
lb_setcpu (pthread_t thread, int cpu)
{
  cpu_set_t set;
  CPU_ZERO (&set);
  CPU_SET (cpu, &set);
  return pthread_setaffinity_np (thread, sizeof (set), &set);
}

inline static int
lb_sleep (time_t sec, long nsec)
{
const struct timespec timeout = { tv_sec: sec, tv_nsec:nsec };
  return nanosleep (&timeout, NULL);
}

void lb_sigsegv_setup ();

#endif /* #ifndef SYSTEM_LB_H_ */

#define FD_CLOSE(fd) do { \
	if(fd >= 0) { \
		_close(fd); \
		fd = -1; \
	} \
} while(0)

#define BUF_FREE(p) do { \
	if (p) { \
		free(p); \
		p = NULL; \
	} \
} while (0)

#endif

#ifdef KERNEL_SYSCALL_API
#define KERNEL_SYSCALL_API

#define KAPI(name) extern (typeof name) *k_##name;
#include "kapi.h"
#undef API

#endif
