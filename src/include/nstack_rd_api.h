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

#ifndef __NSTACK_RD_API_H
#define __NSTACK_RD_API_H

#define NSTACK_IP_BIT_MAX    32

#define MASK_V(ipaddr, masklen)  ((ipaddr) & htonl(~0 << (NSTACK_IP_BIT_MAX - (masklen))))

typedef struct __rd_route_ip_data
{
    unsigned int addr;
    unsigned int masklen;
    unsigned int resev[2];
} rd_ip_data;

typedef struct __rd_type_data
{
    unsigned int value;
    unsigned int attr;
    unsigned char reserved[4];
} rd_type_data;

typedef struct __rd_proto_data
{
    unsigned int value;
    unsigned int attr;
} rd_proto_data;

/* rd table manipulation */
void *nstack_rd_malloc(const char *name);
void *nstack_local_rd_malloc(void);
int nstack_rd_free(const char *name);
void nstack_local_rd_free(void *p);
void nstack_rd_table_clear(void *table);

/* parse rd_config.json */
int nstack_rd_parse(const char *name, void *table);

/* manually insert/delete rd node */
int nstack_rd_ip_node_insert(const char *name, rd_ip_data * data,
                             void *table);
int nstack_rd_ip_node_delete(rd_ip_data * data, void *table);
int nstack_rd_type_node_insert(const char *name, rd_type_data * data,
                               void *table);
int nstack_rd_type_node_delete(rd_type_data * data, void *table);
int nstack_rd_proto_node_insert(const char *name, rd_proto_data * data,
                                void *table);
int nstack_rd_proto_node_delete(rd_proto_data * data, void *table);

#include <netinet/in.h>

#ifndef NSTACK_IP6_ADDR_DEF
#define NSTACK_IP6_ADDR_DEF
typedef struct ip6_addr
{
    union
    {
        uint32_t addr32[4];
        uint16_t addr16[8];
        uint8_t addr8[16];
    };
} ip6_addr_t;
#endif

typedef struct __rd_route_ip6_data
{
    ip6_addr_t addr;
    unsigned int masklen;
} rd_ip6_data;

char *ipv6_ntop(ip6_addr_t host_addr);
int nstack_rd_ip6_node_insert(const char *name, rd_ip6_data * data,
                              void *table);
int nstack_rd_ip6_node_delete(rd_ip6_data * data, void *table);

#define IPV6_ADDR32_IDX     4
#define IPV6_ADDR32_SIZE    32

static inline int ip6_addr_match(struct ip6_addr *a, struct ip6_addr *b,
                                 unsigned int masklen)
{
    int index;
    uint32_t mask;

    for (index = 0; index < IPV6_ADDR32_IDX && masklen >= IPV6_ADDR32_SIZE;
         ++index)
    {
        if (a->addr32[index] != b->addr32[index])
            return 0;

        masklen -= IPV6_ADDR32_SIZE;
    }

    /* masklen is 128 */
    if (index == IPV6_ADDR32_IDX)
    {
        return 1;
    }

    if (index > IPV6_ADDR32_IDX)
        return 0;

    /*compare in network order byte */
    mask = htonl(~0 << (IPV6_ADDR32_SIZE - masklen));

    return (a->addr32[index] & mask) == (b->addr32[index] & mask);
}

#endif // __NSTACK_RD_API_H
