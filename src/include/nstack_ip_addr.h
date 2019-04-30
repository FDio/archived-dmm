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

#ifndef __NSTACK_IP_ADDR_H
#define __NSTACK_IP_ADDR_H

#ifndef ipv4_addr1_u16
#include "types.h"

/* Get one byte from the 4-byte address */
#define ip4_addr1(ipaddr) (((u8_t*)(ipaddr))[0])
#define ip4_addr2(ipaddr) (((u8_t*)(ipaddr))[1])
#define ip4_addr3(ipaddr) (((u8_t*)(ipaddr))[2])
#define ip4_addr4(ipaddr) (((u8_t*)(ipaddr))[3])

/* These are cast to u16_t, with the intent that they are often arguments
 * to printf using the U16_F format from cc.h. */
#define ipv4_addr1_u16(ipaddr) ((u16_t)ip4_addr1(ipaddr))
#define ipv4_addr2_u16(ipaddr) ((u16_t)ip4_addr2(ipaddr))
#define ipv4_addr3_u16(ipaddr) ((u16_t)ip4_addr3(ipaddr))
#define ipv4_addr4_u16(ipaddr) ((u16_t)ip4_addr4(ipaddr))
#define FUZZY_IP_VAR(ipaddr) ipv4_addr3_u16((ipaddr)),ipv4_addr4_u16((ipaddr))
#endif

#include <netinet/in.h>
#include "nstack_securec.h"
#include "nstack_rd_api.h"

static inline int in6_ntoa(char *buf, int size, const struct in6_addr *in6)
{
    return snprintf_s(buf, size, size - 1, "*:*:*:%x:%x:%x:%x:%x",
                      htons(in6->s6_addr16[3]),
                      htons(in6->s6_addr16[4]), htons(in6->s6_addr16[5]),
                      htons(in6->s6_addr16[6]), htons(in6->s6_addr16[7]));
}

static inline const char *inet6_ntoa(const struct in6_addr *addr)
{
    static char buf[64];

    (void) in6_ntoa(buf, sizeof(buf), addr);

    return buf;
}

inline static const char *inet_ntoa_x(const struct sockaddr *addr)
{
    static char buf[32];
    int ret;
    if (addr->sa_family == AF_INET)
    {
        const uint8_t *p =
            (const uint8_t *) &((const struct sockaddr_in *) addr)->
            sin_addr.s_addr;
        ret =
            snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "*.*.%u.%u", p[2],
                       p[3]);
        if (-1 == ret)
        {
            return "NULL";
        }

        return buf;
    }

    if (addr->sa_family == AF_INET6)
        return inet6_ntoa(&((const struct sockaddr_in6 *) addr)->sin6_addr);

    {
        ret =
            snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "family:%d",
                       addr->sa_family);
        if (-1 == ret)
        {
            return "NULL";
        }

        return buf;
    }
}

#endif // __NSTACK_IP_ADDR_H
