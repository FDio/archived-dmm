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

int enable_debug = 1;

#ifdef COLOR_LB_H_

const static struct lb_color lb_color_list[2] = {
  [LB_DEF_COLOR] = {
                    .clear = "\033[0m",
                    .high = "\033[1m",
                    .uline = "\033[4m",
                    .flash = "\033[5m",
                    .rev = "\033[7m",

                    .fblack = "\033[30m",
                    .fr__ = "\033[31m",
                    .f_g_ = "\033[32m",
                    .f__b = "\033[34m",
                    .frg_ = "\033[33m",
                    .fr_b = "\033[35m",
                    .f_gb = "\033[36m",
                    .fwhite = "\033[37m",

                    .bblack = "\033[40m",
                    .br__ = "\033[41m",
                    .b_g_ = "\033[42m",
                    .b__b = "\033[44m",
                    .brg_ = "\033[43m",
                    .br_b = "\033[45m",
                    .b_gb = "\033[46m",
                    .bwhite = "\033[47m",
                    },
  [LB_NO_COLOR] = {
                   .clear = "",
                   .high = "",
                   .uline = "",
                   .flash = "",
                   .rev = "",

                   .fblack = "",
                   .fr__ = "",
                   .f_g_ = "",
                   .f__b = "",
                   .frg_ = "",
                   .fr_b = "",
                   .f_gb = "",
                   .fwhite = "",

                   .bblack = "",
                   .br__ = "",
                   .b_g_ = "",
                   .b__b = "",
                   .brg_ = "",
                   .br_b = "",
                   .b_gb = "",
                   .bwhite = "",
                   },
};

const struct lb_color *lb_color = &lb_color_list[0];
int lb_color_index = 0;

void
lb_set_color (int index)
{
  lb_color_index = index;
  lb_color = &lb_color_list[index];
}

#endif

#ifdef FORMAT_LB_H_

static __thread char s_fmt_buf[64][64];
static __thread uint32_t s_fmt_id = 0;

#if 0
const char *
f_in6 (const struct in6_addr *ip6)
{
  char *buf = s_fmt_buf[(s_fmt_id++) & 63];
  char *p = buf;
  int i;

  for (i = 0; i < 8; ++i)
    {
      uint16_t c, v = htons (ip6->s6_addr16[i]);

      c = v >> 12;
      if (c > 9)
        *p++ = 'A' + c - 10;
      else if (c > 0)
        *p++ = '0' + c;

      c = (v >> 8) & 0xF;
      if (c > 9)
        *p++ = 'A' + c - 10;
      else if (v > 0x00FF)
        *p++ = '0' + c;

      c = (v >> 4) & 0xF;
      if (c > 9)
        *p++ = 'A' + c - 10;
      else if (v > 0x000F)
        *p++ = '0' + c;

      c = v & 0xF;
      if (c > 9)
        *p++ = 'A' + c - 10;
      else
        *p++ = '0' + c;

      *p++ = ':';
    }

  p--;
  *p = 0;
  return buf;
}
#endif

static int
f_in6_f (char *buf, int len, uint16_t val)
{
  uint16_t v;
  int num = 0;

  if (val > 0xFFF)
    {
      if (num >= len)
        return -1;
      v = val >> 12;
      if (v < 10)
        buf[num++] = v + '0';
      else
        buf[num++] = v + 'a' - 10;
    }
  if (val > 0xff)
    {
      if (num >= len)
        return -1;
      v = (val >> 8) & 0xF;
      if (v < 10)
        buf[num++] = v + '0';
      else
        buf[num++] = v + 'a' - 10;
    }
  if (val > 0xf)
    {
      if (num >= len)
        return -1;
      v = (val >> 4) & 0xF;
      if (v < 10)
        buf[num++] = v + '0';
      else
        buf[num++] = v + 'a' - 10;
    }

  if (num >= len)
    return -1;
  v = val & 0xF;
  if (v < 10)
    buf[num++] = v + '0';
  else
    buf[num++] = v + 'a' - 10;

  return num;
}

static void
f_in6_z (const struct in6_addr *addr, int *pos, int *num)
{
  int zero_pos = 8, zero_num = 0;
  int try_pos = -1, try_num = 0;
  int i;

  for (i = 0; i < 8; ++i)
    {
      if (addr->s6_addr16[i] == 0)
        {
          if (try_num)
            {
              try_num++;
            }
          else
            {
              try_pos = i;
              try_num = 1;
            }
        }
      else if (try_num)
        {
          if (try_num > zero_num)
            {
              zero_pos = try_pos;
              zero_num = try_num;
            }
          try_num = 0;
        }
    }

  if (try_num && try_num > zero_num)
    {
      *pos = try_pos;
      *num = try_num;
    }
  else
    {
      *pos = zero_pos;
      *num = zero_num;
    }
}

int
f_in6_s (char *buf, int size, const struct in6_addr *addr)
{
  int ret, i, num = 0;
  int zero_pos, zero_num;

  f_in6_z (addr, &zero_pos, &zero_num);

  if (zero_pos == 0)
    {
      if (num >= size)
        return -1;
      buf[num++] = ':';
    }
  else
    {
      for (i = 0; i < zero_pos; ++i)
        {
          ret = f_in6_f (&buf[num], size - num, htons (addr->s6_addr16[i]));
          if (ret < 0)
            return -1;
          num += ret;
          if (num >= size)
            return -1;
          buf[num++] = ':';
        }
      if (zero_pos == 8)
        {
          buf[--num] = 0;
          return num;
        }
    }

  if (zero_pos + zero_num == 8)
    {
      if (num >= size)
        return -1;
      buf[num++] = ':';
    }
  else
    {
      for (i = zero_pos + zero_num; i < 8; ++i)
        {
          if (num >= size)
            return -1;
          buf[num++] = ':';
          ret = f_in6_f (&buf[num], size - num, htons (addr->s6_addr16[i]));
          if (ret < 0)
            return -1;
          num += ret;
        }
    }

  if (num >= size)
    return -1;
  buf[num] = 0;

  return num;
}

const char *
f_in6_r (const struct in6_addr *addr, char *buf, int buflen)
{
  if (f_in6_s (buf, buflen, addr) <= 0)
    return NULL;
  return buf;
}

const char *
f_in6 (const struct in6_addr *addr)
{
  char *buf = s_fmt_buf[(s_fmt_id++) & 63];
  return f_in6_r (addr, buf, sizeof (s_fmt_buf[0]));
}

const char *
f_inaddr (const struct sockaddr_in *addr)
{
  char *buf = s_fmt_buf[(s_fmt_id++) & 63];
  char *p = buf;
  const uint8_t *ip = (uint8_t *) & addr->sin_addr.s_addr;
  const uint16_t pt = ntohs (addr->sin_port);

#define IPP(v) do { \
	if (v > 99) { *p++ = '0' + v / 100 % 10; } \
	if (v > 9) { *p++ = '0' + v / 10 % 10; } \
	*p++ = '0' + v % 10; \
} while (0)

#define PTP(v) do { \
	if (v > 9999) { *p++ = '0' + v / 10000 % 10; } \
	if (v > 999) { *p++ = '0' + v / 1000 % 10; } \
	IPP(v); \
} while (0)

  IPP (ip[0]);
  *p++ = '.';
  IPP (ip[1]);
  *p++ = '.';
  IPP (ip[2]);
  *p++ = '.';
  IPP (ip[3]);
  *p++ = ':';
  PTP (pt);
  *p = 0;

  return buf;
}

const char *
f_in6addr (const struct sockaddr_in6 *addr)
{
  char *p, *buf = s_fmt_buf[(s_fmt_id++) & 63];
  const uint16_t pt = htons (addr->sin6_port);
  int len = f_in6_s (buf, sizeof (s_fmt_buf[0]), &addr->sin6_addr);

  if (len < 0)
    return "";

  p = buf + len;
  *p++ = '.';
  PTP (pt);
  *p = 0;

  return buf;
}

inline static int
r_uint_use (uint64_t val)
{
  const static uint64_t LB_VAL[21] = {
    0,
    9,
    99,
    999,
    9999,
    99999,
    999999,
    9999999,
    99999999,
    999999999,
    9999999999,
    99999999999,
    999999999999,
    9999999999999,
    99999999999999,
    999999999999999,
    9999999999999999,
    99999999999999999,
    999999999999999999,
    9999999999999999999u,
    18446744073709551615u,
    /*  --%%%***+++###^^^@@@ */
  };

  int a = 1, b = 20;

  do
    {
      int i = (a + b) / 2;
      if (val > LB_VAL[i])
        a = i + 1;
      else
        b = i;
    }
  while (a != b);

  return a;
}

inline static int
r_uint_wide (uint64_t val)
{
  int wide = r_uint_use (val);

  wide = wide + (wide - 1) / 3;

  return wide;
}

inline static void
r_uint_fmt (char *buf, uint64_t val, int wide)
{
  char *p = buf + wide;

  *p-- = 0;

  while (1)
    {
      *p-- = ('0' + val % 10);
      if ((val /= 10) == 0)
        break;

      *p-- = ('0' + val % 10);
      if ((val /= 10) == 0)
        break;

      *p-- = ('0' + val % 10);
      if ((val /= 10) == 0)
        break;

      *p-- = ',';
    }

  while (p >= buf)
    *p-- = ' ';
}

int
r_uint (char *buf, uint64_t val, int wide)
{
  const int size = r_uint_wide (val);

  if (size > wide)
    wide = size;

  r_uint_fmt (buf, val, wide);

  return wide;
}

inline int
s_uint (char *buf, uint64_t val)
{
  char *p = buf;

#define F_NUM(n) if (val >= n) { *p++ = '0' + val / n % 10; }
#define C_NUM(n) if (val >= n) { *p++ = '0' + val / n % 10; *p++ = ','; }

  if (val >= 10000000ul)
    {
      if (val >= 1000000000000ul)
        {
          F_NUM (10000000000000000000ul);
          C_NUM (1000000000000000000ul);
          F_NUM (100000000000000000ul);
          F_NUM (10000000000000000ul);
          C_NUM (1000000000000000ul);
          F_NUM (100000000000000ul);
          F_NUM (10000000000000ul);
          C_NUM (1000000000000ul);
        }
      F_NUM (100000000000ul);
      F_NUM (10000000000ul);
      C_NUM (1000000000ul);
      F_NUM (100000000ul);
      F_NUM (10000000ul);
    }
  C_NUM (1000000ul);
  F_NUM (100000ul);
  F_NUM (10000ul);
  C_NUM (1000ul);
  F_NUM (100ul);
  F_NUM (10ul);
  *p++ = '0' + val % 10;
  *p = 0;

#undef F_NUM
#undef C_NUM
  return p - buf;
}

const char *
f_uint (uint64_t val)
{
  char *buf = s_fmt_buf[(s_fmt_id++) & 63];
  (void) s_uint (buf, val);
  return buf;
}

#endif
#ifdef PARSE_LB_H_

#define IS_DIGIT(c) ((c) >= '0' && (c) <= '9')
#define IS_hex(c) ((c) >= 'a' && (c) <= 'f')
#define IS_HEX(c) ((c) >= 'A' && (c) <= 'F')

uint64_t
p_hex (const char *arg, const char **end)
{
  int i;
  uint64_t val = 0;

  while (*arg)
    {
      if (IS_DIGIT (*arg))
        val = (val << 4) | (uint64_t) (*arg++ - '0');
      else if (IS_hex (*arg))
        val = (val << 4) | (uint64_t) (*arg++ - 'a' + 0xa);
      else if (IS_HEX (*arg))
        val = (val << 4) | (uint64_t) (*arg++ - 'A' + 0xA);
      else
        break;
      if (val > 0x0FFFffffFFFFffff)
        break;
    }

  if (end)
    *end = arg;
  return val;
}

#define P_UINT_RET(ret, out) ((*end = (out)), (ret))

uint64_t
p_uint (const char *arg, uint64_t max, const char **end)
{
  int i;
  uint64_t v;
  const char *out;

  if (!end)
    end = &out;

  if (!arg)
    goto P_UINT_ERR;

  if (*arg == '0')
    {
      if (IS_DIGIT (arg[1]))
        goto P_UINT_ERR;
      return P_UINT_RET (0, arg + 1);
    }

  if (!IS_DIGIT (*arg))
    return P_UINT_RET (0, NULL);

  v = *arg++ - '0';
  if (v > max)
    goto P_UINT_ERR;

  for (i = 2; i <= 19; ++i)
    {
      if (!IS_DIGIT (*arg))
        return P_UINT_RET (v, arg);
      v = v * 10 + (*arg++ - '0');
      if (v > max)
        goto P_UINT_ERR;
    }

  if (IS_DIGIT (*arg))
    {
      uint64_t n;
      if (v > (UINT64_MAX / 10))
        goto P_UINT_ERR;
      n = v * 10;
      if (UINT64_MAX - n > (*arg - '0'))
        goto P_UINT_ERR;
      v = n + (*arg - '0');
      if (v > max)
        goto P_UINT_ERR;
      arg++;
      if (IS_DIGIT (*arg))
        goto P_UINT_ERR;
    }

  return P_UINT_RET (v, arg);

P_UINT_ERR:
  return P_UINT_RET (UINT64_MAX, NULL);
}

inline uint32_t
p_ip (const char **arg)
{
  uint32_t b1, b2, b3, b4;
  const char *p = *arg;

  b1 = (uint32_t) p_uint (p, 255, &p);
  if (!p || *p++ != '.')
    goto P_IP_ERR;
  b2 = (uint32_t) p_uint (p, 255, &p);
  if (!p || *p++ != '.')
    goto P_IP_ERR;
  b3 = (uint32_t) p_uint (p, 255, &p);
  if (!p || *p++ != '.')
    goto P_IP_ERR;
  b4 = (uint32_t) p_uint (p, 255, &p);
  if (!p)
    goto P_IP_ERR;

  *arg = p;
  return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;

P_IP_ERR:
  *arg = NULL;
  return 0;
}

int
p_addr (const char *arg, struct sockaddr_in *addr)
{
  uint16_t port;

  if (*arg != ':')
    {
      uint32_t ip = p_ip (&arg);
      if (!arg)
        return -1;
      addr->sin_addr.s_addr = htonl (ip);
      if (*arg == 0)
        return 0;
      if (*arg != ':')
        return -1;
      arg++;
    }

  port = (uint16_t) p_uint (arg, 0xffff, &arg);
  if (!arg || *arg != 0)
    return -1;
  addr->sin_port = htons (port);

  return 0;
}

const char *
p_addr_set (const char *arg, struct inaddrs *addr, uint32_t flag)
{
  addr->ip = p_ip (&arg);
  if (!arg)
    return NULL;

  if (!(flag & PA_NO_TO_IP) && *arg == '-')
    {
      uint8_t to;
      to = (uint8_t) p_uint (arg + 1, 255, &arg);
      if (!arg)
        return NULL;
      addr->ip_num = to - (uint8_t) addr->ip;
      if (addr->ip_num >= 0)
        ++addr->ip_num;
      else if (flag & PA_MAY_INV_IP)
        --addr->ip_num;
      else
        return NULL;
    }
  else if (!(flag & PA_NO_NUM_IP) && *arg == '+')
    {
      addr->ip_num = (int) p_uint (arg + 1, 0x7FFFffff, &arg);
      if (!arg || addr->ip_num == 0 || 0xFFFFFFFF - addr->ip < addr->ip_num)
        return NULL;
    }
  else
    {
      addr->ip_num = 1;
    }

  if ((flag & PA_DEF_PORT) == PA_NO_PORT)
    return arg;

  if (*arg != ':')
    {
      if ((flag & PA_DEF_PORT) == PA_MUST_PORT)
        return NULL;
      if ((flag & PA_DEF_PORT) == PA_DEF_PORT)
        {
          addr->port = (uint16_t) (flag);
          addr->port_num = 1;
        }
      else
        {
          addr->port = 0;
          addr->port_num = 0;
        }
      return arg;
    }

  addr->port = (uint16_t) p_uint (arg + 1, 0xffff, &arg);
  if (!arg)
    return NULL;

  if (!(flag & PA_NO_TO_PORT) && *arg == '-')
    {
      uint16_t to = (uint16_t) p_uint (arg + 1, 0xffff, &arg);
      if (!arg || to < addr->port)
        return NULL;
      addr->port_num = to - addr->port + 1;
    }
  else if (!(flag & PA_NO_NUM_PORT) && *arg == '+')
    {
      addr->port_num = (uint16_t) p_uint (arg + 1, 0xffff, &arg);
      if (!arg || addr->port_num == 0 || 0xFFFF - addr->port < addr->port_num)
        return NULL;
    }
  else
    {
      addr->port_num = 1;
    }

  if (flag & PA_MULTI_ONE)
    {
      if (addr->ip_num > 1 && addr->port_num > 1)
        return NULL;
    }

  return arg;
}

inline static const char *
pal_trim (const char *arg, uint32_t flag)
{
  if (flag & PAL_NO_SPACE)
    return arg;

  if (flag & PAL_WITH_NL)
    {
      while (*arg == ' ' || *arg == '\t' || *arg == '\r' || *arg == '\n')
        arg++;
    }
  else
    {
      while (*arg == ' ' || *arg == '\t')
        arg++;
    }

  return arg;
}

int
p_addr_list (const char *arg, struct inaddrs *list, int num, uint32_t flag,
             const char **end)
{
  int count = 0;

  while (count < num)
    {
      arg = pal_trim (arg, flag);
      arg = p_addr_set (arg, list, flag);
      count++;
      if (!arg)
        return -count;
      arg = pal_trim (arg, flag);
      if (*arg != ',')
        break;
      arg++;
      list++;
    }

  if (end)
    *end = arg;
  else if (*arg)
    return -count;

  return count;
}

int
addr_total (const struct inaddrs *list, int num, uint32_t mode)
{
  int total = 0;

  mode &= PAL_CROSS_MASK;

  for (--num; num >= 0; --num)
    {
      if (mode == PAL_IP_X_PORT || mode == PAL_PORT_X_IP)
        {
          total += list[num].ip_num * list[num].port_num;
        }
      else if (mode == PAL_INC_BOTH)
        {
          int iip = 0;
          uint16_t iport = 0;
          do
            {
              total++;
              if (++iip == list[num].ip_num)
                iip = 0;
              if (++iport == list[num].port_num)
                iport = 0;
            }
          while (iip != 0 && iport != 0);
        }
      else
        return -1;
    }

  return total;
}

int
addr_layout (const struct inaddrs *list, int list_num,
             struct sockaddr_in *addr, int addr_num, uint32_t mode)
{
  uint16_t ipt;
  int i, iip, count = 0;

  mode &= PAL_CROSS_MASK;

  if (mode == PAL_IP_X_PORT)
    {
      for (i = 0; i < list_num; ++i)
        {
          if (count + list[i].ip_num * list[i].port_num > addr_num)
            return -1;
          for (iip = 0; iip < list[i].ip_num; ++iip)
            {
              for (ipt = 0; ipt < list[i].port_num; ++ipt)
                {
                  addr[count].sin_family = AF_INET;
                  addr[count].sin_addr.s_addr = htonl (list[i].ip + iip);
                  addr[count].sin_port = htons (list[i].port + ipt);
                  count++;
                }
            }
        }
    }
  else if (mode == PAL_PORT_X_IP)
    {
      for (i = 0; i < list_num; ++i)
        {
          if (count + list[i].ip_num * list[i].port_num > addr_num)
            return -1;
          for (ipt = 0; ipt < list[i].port_num; ++ipt)
            {
              for (iip = 0; iip < list[i].ip_num; ++iip)
                {
                  addr[count].sin_family = AF_INET;
                  addr[count].sin_addr.s_addr = htonl (list[i].ip + iip);
                  addr[count].sin_port = htons (list[i].port + ipt);
                  count++;
                }
            }
        }
    }
  else if (mode == PAL_INC_BOTH)
    {
      for (i = 0; i < list_num; ++i)
        {
          do
            {
              if (count >= addr_num)
                return -1;
              addr[count].sin_family = AF_INET;
              addr[count].sin_addr.s_addr = htonl (list[i].ip + iip);
              addr[count].sin_port = htons (list[i].port + ipt);
              count++;
              if (++iip >= list[i].ip_num)
                iip = 0;
              if (++ipt >= list[i].port_num)
                ipt = 0;
            }
          while (iip != 0 && ipt != 0);
        }
    }
  else
    {
      return -1;
    }

  return count;
}

inline static const char *
p_ip6_se (const char *p, uint16_t * val)
{
  int i;
  uint32_t v = 0;

  for (i = 0; i < 4; ++i)
    {
      if (p[i] >= '0' && p[i] <= '9')
        v = (v << 4) + p[i] - '0';
      else if (p[i] >= 'a' && p[i] <= 'f')
        v = (v << 4) + p[i] - 'a' + 10;
      else if (p[i] >= 'A' && p[i] <= 'F')
        v = (v << 4) + p[i] - 'A' + 10;
      else
        break;
    }

  if (i == 0)
    return NULL;

  *val = htons (v);
  return p + i;
}

const char *
p_ip6 (const char *pos, struct in6_addr *ip)
{
  int zero = -1, num = 0;
  const char *last;

  if (*pos == ':')
    {
      pos++;
      if (*pos != ':')
        return NULL;
      pos++;
      zero = 0;
    }

  last = pos;

  while (*pos)
    {
      pos = p_ip6_se (pos, &ip->s6_addr16[num]);
      if (!pos)
        {
          if (zero == num)
            break;
          return NULL;
        }

      num++;
      if (num == 8)
        break;

      if (*pos == ':')
        {
          pos++;
          if (*pos == ':')
            {
              if (zero >= 0)
                return NULL;
              zero = num;
              pos++;
            }
          last = pos;
        }
      else if (*pos == '.')
        {
          if (num > 6)
            return NULL;
          *(uint32_t *) (&ip->s6_addr16[num - 1]) = htonl (p_ip (&last));
          if (!last)
            return NULL;
          pos = last;
          num++;
          break;
        }
      else
        {
          break;
        }
    }

  if (num == 0)
    {
      if (zero != 0)
        return NULL;
      ip->s6_addr32[0] = htonl (0);
      ip->s6_addr32[1] = htonl (0);
      ip->s6_addr32[2] = htonl (0);
      ip->s6_addr32[3] = htonl (0);
      return pos;
    }

  if (num < 8)
    {
      int i, cp;
      if (zero < 0)
        return NULL;
      /* move */
      for (i = num - 1, cp = 7; i >= zero; --i)
        ip->s6_addr16[cp--] = ip->s6_addr16[i];
      /* fill 0 */
      for (i = num, cp = zero; i < 8; ++i)
        ip->s6_addr16[cp++] = htons (0);
    }
  else if (zero >= 0)
    {
      return NULL;
    }

  return pos;
}

int
p_addr6 (const char *arg, struct sockaddr_in6 *addr)
{
  uint16_t port;

  if (*arg != '.')
    {
      arg = p_ip6 (arg, &addr->sin6_addr);
      if (!arg)
        return -1;
      if (*arg == 0)
        return 0;
      if (*arg != '.')
        return -1;
      arg++;
    }

  port = (uint16_t) p_uint (arg, 0xffff, &arg);
  if (!arg || *arg != 0)
    return -1;
  addr->sin6_port = htons (port);

  return 0;
}

#endif
#ifdef UNIT_LB_H_

const static uint64_t UNITS[UNIT_NUM] = {
  [UNIT_1] = 1,
  [UNIT_k] = 1000,
  [UNIT_m] = 1000 * 1000,
  [UNIT_g] = 1000 * 1000 * 1000,
  [UNIT_w] = 10000,
  [UNIT_K] = 1024,
  [UNIT_M] = 1024 * 1024,
  [UNIT_G] = 1024 * 1024 * 1024,

  [UNIT_hour] = 60 * 60,
  [UNIT_min] = 60,
  [UNIT_sec] = 1,

  [UNIT_hn] = 1000ull * 1000 * 1000 * 60 * 60,
  [UNIT_mn] = 1000ull * 1000 * 1000 * 60,
  [UNIT_sn] = 1000 * 1000 * 1000,
  [UNIT_1n] = 1000 * 1000 * 1000,
  [UNIT_ms] = 1000 * 1000,
  [UNIT_us] = 1000,
  [UNIT_ns] = 1,

  [UNIT_PC] = 1,
};

#define P_UNIT_END(ret, end) ({ \
	*arg = (end); \
	if (unit) *unit = UNITS[ret]; \
	ret; \
})

int
p_unit (const char **arg, int mask, uint64_t * unit)
{
  const char *opt = *arg;
  int ret;

  switch (*opt)
    {
    case 'w':
      ret = UNIT_w;
      break;
    case 'm':
      if ((mask & UB_ms) && opt[1] == 's')
        return P_UNIT_END (UNIT_ms, opt + 2);
      if (mask & UB_min)
        return P_UNIT_END (UNIT_min, opt + 1);
      ret = UNIT_m;
      break;
    case 'k':
      ret = UNIT_k;
      break;
    case 'g':
      ret = UNIT_g;
      break;

    case 'h':
      ret = UNIT_hour;
      break;
    case 's':
      ret = UNIT_sec;
      break;
    case 'u':
      if ((mask & UB_us) && opt[1] == 's')
        return P_UNIT_END (UNIT_us, opt + 2);
      goto NO_UNIT;
    case 'n':
      if ((mask & UB_ns) && opt[1] == 's')
        return P_UNIT_END (UNIT_ns, opt + 2);
      goto NO_UNIT;

    case '%':
      ret = UNIT_PC;
      break;

    case 'K':
      ret = UNIT_K;
      break;
    case 'M':
      ret = UNIT_M;
      break;
    case 'G':
      ret = UNIT_G;
      break;

    default:
      goto NO_UNIT;
    }

  if ((1 << ret) & mask)
    return P_UNIT_END (ret, opt + 1);

NO_UNIT:
  if (0 == (mask & UB_1))
    return -1;

  return P_UNIT_END (UNIT_1, opt);
}

#endif
#ifdef CACHED_OUTPUT_LB_H_

int
co_app_ch (char buf[], char ch)
{
  struct cohead *head = (struct cohead *) buf;

  buf += sizeof (struct cohead);

  if (head->free > 3)
    {
      buf += (head->size - head->free);
      buf[0] = ch;
      buf[1] = 0;
      head->free -= 1;
    }
  else
    {
      (void) fprintf (CO_OUT (head), "%s%c", buf, ch);
      buf[0] = 0;
      head->free = head->size;
    }

  return 1;
}

int
co_append (char buf[], cosize_t max, const char *fmt, ...)
{
  int ret;
  va_list ap;
  struct cohead *head = (struct cohead *) buf;

  /* no space for max+1 size -> output if cached */
  if (max >= head->free && head->free < head->size)
    _co_flush (head);

  /* enough space -> try cache format */
  if (max < head->free)
    {
      char *p = buf + (sizeof (struct cohead) + head->size - head->free);
      va_start (ap, fmt);
      ret = vsnprintf (p, head->free, fmt, ap);
      va_end (ap);
      if (ret >= 0 && ret < head->free)
        {
          head->free -= ret;
          return ret;
        }
    }

  /* no space or format failed -> output if cached */
  if (head->free != head->size)
    _co_flush (head);

  /* direct output */
  va_start (ap, fmt);
  ret = fprintf (CO_OUT (head), fmt, ap);
  va_end (ap);

  return ret;
}

int
co_wr_uint (char buf[], uint64_t val, int wide)
{
  struct cohead *head = (struct cohead *) buf;
  int size = r_uint_wide (val);
  char *p;

  if (size > wide)
    wide = size;

  if (head->free <= wide)
    _co_flush (head);

  if (head->free <= wide)
    {
      assert (0);
    }

  p = buf + (sizeof (struct cohead) + head->size - head->free);

  r_uint_fmt (p, val, wide);

  head->free -= wide;

  return wide;
}

#endif

#ifdef SYSTEM_LB_H_

pthread_t
lb_thread (void *(*proc) (void *), void *arg, const char *fmt, ...)
{
  pthread_t tid;
  int ret;

  ret = pthread_create (&tid, NULL, proc, arg);
  if (ret)
    return 0;

  if (fmt)
    {
      char name[20];
      va_list args;

      va_start (args, fmt);
      ret = vsnprintf (name, sizeof (name), fmt, args);
      va_end (args);

      if (ret > 0)
        {
          name[sizeof (name) - 1] = 0;
          (void) pthread_setname_np (tid, name);
        }
    }

  return tid;
}

static void
lb_sigsegv_proc (int s)
{
  int num;
  void *buf[128];

  out ("Signal SIGSEGV, Segmentation fault!\n");

  num = backtrace (buf, 128);
  if (num > 0)
    backtrace_symbols_fd (buf, num, STDOUT_FILENO);
  exit (1);
}

void
lb_sigsegv_setup ()
{
  struct sigaction s = { 0 };

  (void) sigemptyset (&s.sa_mask);

  s.sa_flags = SA_NODEFER;
  s.sa_handler = (void *) lb_sigsegv_proc;
  (void) sigaction (SIGSEGV, &s, NULL);
}

#endif

#ifdef KERNEL_SYSCALL_API

#define KAPI(name) (typeof name) *k_##name = ##name;
#include "kapi.h"
#undef API

void
kapi_init ()
{
#define KAPI(name) k_##name = ld_load;
}

#endif
