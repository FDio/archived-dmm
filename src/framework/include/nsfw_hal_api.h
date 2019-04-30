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

#ifndef _HAL_API_H_
#define _HAL_API_H_

#include "nsfw_branch_prediction.h"
#include "nsfw_maintain_api.h"

#ifdef __cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
#endif

#define HAL_IO_REGISTER(name, ops) \
    static __attribute__((__constructor__)) void __hal_register_##name(void)  \
    {\
        hal_io_adpt_register(ops); \
    } \

#define HAL_ETH_MAX_QUEUE_NUM    MAX_THREAD_NUM

#define HAL_ETH_QUEUE_STAT_CNTRS 16

#define HAL_MAX_NIC_NUM 4096
COMPAT_PROTECT_RETURN(HAL_MAX_NIC_NUM, 4096);

#define HAL_MAX_SLAVES_PER_BOND 2

#define HAL_MAX_NIC_NAME_LEN 256

#define HAL_MAX_PCI_ADDR_LEN 16

#define HAL_SCRIPT_LENGTH       256

#define HAL_MAX_DRIVER_NAME_LEN 128

#define HAL_MAX_PATH_LEN        4096    //max path length on linux is 4096

/**
 * TX offload capabilities of a device.
 */
#define HAL_ETH_TX_OFFLOAD_IPV4_CKSUM  0x00000002
#define HAL_ETH_TX_OFFLOAD_UDP_CKSUM   0x00000004
#define HAL_ETH_TX_OFFLOAD_TCP_CKSUM   0x00000008

/**
 * Hal Instance Handler
 */
typedef struct hal_hdl
{
    int id;
} hal_hdl_t;

/**
 * Ethernet device capability
 */
struct hal_netif_hw_feature
{
    uint8_t rx_csum_ip;
    uint8_t rx_csum_l4;
    uint8_t rx_lro;
    uint8_t tx_csum_ip;
    uint8_t tx_csum_udp;
    uint8_t tx_csum_tcp;
    uint8_t tx_tso;
};

struct lwip_pci_zone
{
    char pci_addr[HAL_MAX_PCI_ADDR_LEN];
    char nic_name[HAL_MAX_NIC_NAME_LEN];
};

typedef struct hal_netif_stats
{
    uint64_t ipackets;  /**< Number of successfully received packets. */
    uint64_t opackets;  /**< Number of successfully transmitted packets.*/
    uint64_t ibytes;    /**< Number of successfully received bytes. */
    uint64_t obytes;    /**< Number of successfully transmitted bytes. */
    uint64_t imissed;   /**< Total of RX packets dropped by the HW. */
    uint64_t ierrors;   /**< Number of erroneous received packets. */
    uint64_t oerrors;   /**< Number of failed transmitted packets. */
    uint64_t rx_nombuf; /**< Number of RX mbuf allocation failures. */

    uint64_t q_ipackets[HAL_ETH_QUEUE_STAT_CNTRS]; /**< Total number of queue RX packets. */
    uint64_t q_opackets[HAL_ETH_QUEUE_STAT_CNTRS]; /**< Total number of queue TX packets. */
    uint64_t q_ibytes[HAL_ETH_QUEUE_STAT_CNTRS];   /**< Total number of successfully received queue bytes. */
    uint64_t q_obytes[HAL_ETH_QUEUE_STAT_CNTRS];   /**< Total number of successfully transmitted queue bytes. */
    uint64_t q_errors[HAL_ETH_QUEUE_STAT_CNTRS];   /**< Total number of queue packets received that are dropped. */
} hal_netif_stats_t;

struct hal_netif_hw_config
{
    uint32_t rx_csum_ip_flag:1,
        rx_csum_l4_flag:1,
        rx_lro_flag:1, tx_csum_ip_flag:1, tx_csum_l4_flag:1, tx_tso_flag:1;
};
extern struct hal_netif_hw_config spl_hal_port_hw_config[HAL_MAX_NIC_NUM];
/**
 * Ethernet device config
 */
typedef struct hal_netif_config
{
    struct hal_netif_hw_config hw_config;
    struct
    {
        uint32_t hw_vlan_filter:1;
        uint32_t hw_vlan_strip:1;
        uint32_t rsv30:30;
    } bit;

    struct
    {
        uint32_t queue_num;
        uint32_t ring_size[HAL_ETH_MAX_QUEUE_NUM];
        void *ring_pool[HAL_ETH_MAX_QUEUE_NUM];
    } rx;

    struct
    {
        uint32_t queue_num;
        uint32_t ring_size[HAL_ETH_MAX_QUEUE_NUM];
    } tx;

    uint8_t is_slave;
} hal_netif_config_t;

/* IO using DPDK interface */
typedef struct dpdk_if
{
    uint8_t port_id;                      /**< DPDK port identifier */
    uint8_t is_slave;
    uint8_t slave_num;
    uint8_t slave_port[HAL_MAX_SLAVES_PER_BOND];

    uint32_t hw_vlan_filter:1;
    uint32_t hw_vlan_strip:1;
    uint32_t rsv30:30;

    uint32_t rx_queue_num;
    uint32_t rx_ring_size[HAL_ETH_MAX_QUEUE_NUM];
    void *rx_pool[HAL_ETH_MAX_QUEUE_NUM];

    uint32_t tx_queue_num;
    uint32_t tx_ring_size[HAL_ETH_MAX_QUEUE_NUM];

    char pci_addr[HAL_MAX_PCI_ADDR_LEN];
    char nic_name[HAL_MAX_NIC_NAME_LEN];
    char nic_type[HAL_MAX_NIC_NAME_LEN];
    char driver_name[HAL_MAX_DRIVER_NAME_LEN];
} dpdk_if_t;

typedef struct netif_inst
{
    enum
    {
        NETIF_STATE_FREE = 0,
        NETIF_STATE_ACTIVE
    } state;

    hal_hdl_t hdl;
    struct hal_netif_hw_config hw_config;
    const struct netif_ops *ops;      /**< Implementation specific methods */

    union
    {
        dpdk_if_t dpdk_if;                /**< using DPDK for IO */
    } data;

} netif_inst_t;

typedef struct netif_ops
{
    const char *name;
    int (*init_global) (int argc, char **argv);
    int (*init_local) (void);
    int (*open) (netif_inst_t * inst, const char *name, const char *type);
    int (*close) (netif_inst_t * inst);
    int (*start) (netif_inst_t * inst);
    int (*stop) (netif_inst_t * inst);
    int (*bond) (netif_inst_t * inst, const char *bond_name,
                 uint8_t slave_num, netif_inst_t * slave[]);
      uint32_t(*mtu) (netif_inst_t * inst);
    int (*macaddr) (netif_inst_t * inst, void *mac_addr);
    int (*capability) (netif_inst_t * inst,
                       struct hal_netif_hw_feature * info);
      uint16_t(*recv) (netif_inst_t * inst, uint16_t queue_id,
                       void **rx_pkts, uint16_t nb_pkts);
      uint16_t(*send) (netif_inst_t * inst, uint16_t queue_id,
                       void **tx_pkts, uint16_t nb_pkts);
      uint32_t(*link_status) (netif_inst_t * inst);
    int (*stats) (netif_inst_t * inst, hal_netif_stats_t * stats);
    int (*stats_reset) (netif_inst_t * inst);
    int (*config) (netif_inst_t * inst, hal_netif_config_t * conf);
    int (*mcastaddr) (netif_inst_t * inst, void *mc_addr_set,
                      void *mc_addr, uint32_t nb_mc_addr);
    int (*add_mac) (netif_inst_t * inst, void *mc_addr);
    int (*rmv_mac) (netif_inst_t * inst, void *mc_addr);
    int (*allmcast) (netif_inst_t * inst, uint8_t enable);
    int (*port_switch) (netif_inst_t * inst);
    int (*get_bond_primary) (netif_inst_t * inst);
    int (*check_rss) (netif_inst_t * inst, uint32_t saddr, uint32_t daddr,
                      uint16_t sport, uint16_t dport,
                      uint16_t * thread_index);
    int (*check_rss6) (netif_inst_t * inst, uint32_t saddr[4],
                       uint32_t daddr[4], uint16_t sport, uint16_t dport,
                       uint16_t * thread_index);
} netif_ops_t;

int hal_init_global(int argc, char **argv);
int hal_init_local();
hal_hdl_t hal_create(const char *name, const char *nic_type,
                     hal_netif_config_t * conf);
hal_hdl_t hal_bond(const char *bond_name, uint8_t slave_num,
                   hal_hdl_t slave_hdl[]);

#define hal_is_valid(hdl) ((hdl.id >= 0) && (hdl.id < HAL_MAX_NIC_NUM))

#define hal_is_equal(hdl_left, hdl_right) (hdl_left.id == hdl_right.id)

int hal_close(hal_hdl_t hdl);
int hal_stop(hal_hdl_t hdl);
uint32_t hal_get_mtu(hal_hdl_t hdl);
void hal_get_macaddr(hal_hdl_t hdl, void *mac_addr);
void hal_get_capability(hal_hdl_t hdl, struct hal_netif_hw_feature *info);
uint16_t hal_recv_packet(hal_hdl_t hdl, uint16_t queue_id, void **rx_pkts,
                         uint16_t nb_pkts);
uint16_t hal_send_packet(hal_hdl_t hdl, uint16_t queue_id, void **tx_pkts,
                         uint16_t nb_pkts);
uint32_t hal_link_status(hal_hdl_t hdl);
int hal_stats(hal_hdl_t hdl, hal_netif_stats_t * stats);
void hal_stats_reset(hal_hdl_t hdl);
int hal_add_mcastaddr(hal_hdl_t hdl, void *mc_addr_set,
                      void *mc_addr, uint32_t nb_mc_addr);
int hal_del_mcastaddr(hal_hdl_t hdl, void *mc_addr_set,
                      void *mc_addr, uint32_t nb_mc_addr);
void hal_set_allmulti_mode(hal_hdl_t hdl, uint8_t enable);
uint32_t hal_is_nic_exist(const char *name);
hal_hdl_t hal_get_invalid_hdl();
int hal_bond_switch(const char *bond_name);
int hal_get_bond_primary(const char *bond_name);
int hal_snprintf(char *buffer, size_t buflen, const char *format, ...);
int hal_run_script(const char *cmd, char *result_buf, size_t max_result_len);
int hal_is_script_valid(const char *cmd);
void hal_io_adpt_register(const netif_ops_t * ops);

int hal_check_rss(hal_hdl_t hdl, uint32_t saddr, uint32_t daddr,
                  uint16_t sport, uint16_t dport, uint16_t * thread_index);
int hal_check_rss6(hal_hdl_t hdl, uint32_t saddr[4], uint32_t daddr[4],
                   uint16_t sport, uint16_t dport, uint16_t * thread_index);

struct hal_netif_hw_config *hal_get_netif_hw_config(hal_hdl_t hdl);

#ifdef __cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif
