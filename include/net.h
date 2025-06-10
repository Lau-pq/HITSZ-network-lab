#ifndef NET_H
#define NET_H
#include "buf.h"
#include "config.h"
#include "map.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
typedef enum net_protocol {
    NET_PROTOCOL_ARP = 0x0806,
    NET_PROTOCOL_IP = 0x0800,
    NET_PROTOCOL_IP6 = 0x86DD,
    NET_PROTOCOL_ICMP = 1,
    NET_PROTOCOL_UDP = 17,
    NET_PROTOCOL_TCP = 6,
} net_protocol_t;

typedef void (*net_handler_t)(buf_t *buf, uint8_t *src);

#define NET_MAC_LEN 6  // mac地址长度
#define NET_IP_LEN 4   // ip地址长度

extern uint8_t net_if_mac[NET_MAC_LEN];
extern uint8_t net_if_ip[NET_IP_LEN];
extern uint8_t net_if_ip6[16];   // IPv6地址
extern buf_t rxbuf, txbuf;  // 一个buf足够单线程使用

int net_init();
void net_poll();
int net_in(buf_t *buf, uint16_t protocol, uint8_t *src);
int net_in6(buf_t *buf, uint16_t protocol, uint8_t *src_ip6);
void net_add_protocol(uint16_t protocol, net_handler_t handler);
#endif