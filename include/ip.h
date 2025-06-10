#ifndef IP_H
#define IP_H

#include "net.h"

#pragma pack(1)
typedef struct ip_hdr {
    uint8_t hdr_len : 4;         // 首部长, 4字节为单位
    uint8_t version : 4;         // 版本号
    uint8_t tos;                 // 服务类型
    uint16_t total_len16;        // 总长度
    uint16_t id16;               // 标识符
    uint16_t flags_fragment16;   // 标志与分段
    uint8_t ttl;                 // 存活时间
    uint8_t protocol;            // 上层协议
    uint16_t hdr_checksum16;     // 首部校验和
    uint8_t src_ip[NET_IP_LEN];  // 源IP
    uint8_t dst_ip[NET_IP_LEN];  // 目标IP
} ip_hdr_t;
#pragma pack()

#define IP_HDR_LEN_PER_BYTE 4       // ip包头长度单位
#define IP_HDR_OFFSET_PER_BYTE 8    // ip分片偏移长度单位
#define IP_VERSION_4 4              // ipv4
#define IP_MORE_FRAGMENT (1 << 13)  // ip分片mf位
void ip_in(buf_t *buf, uint8_t *src_mac);
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol);
void ip_init();

#define NET_IP6_LEN 16
#define IP_VERSION_6 6
#define IP6_DEFAULT_HOP_LIMIT 64     // IPv6默认跳数限制

#pragma pack(1)
typedef struct ip6_hdr {
    uint32_t version_tc_flowlabel;    // 版本(4位),流量类别(8位),流标签(20位)
    uint16_t payload_len;             // 有效载荷长度
    uint8_t next_header;              // 下一个头部
    uint8_t hop_limit;                // 跳数限制
    uint8_t src_ip[NET_IP6_LEN];      // 源IPv6地址
    uint8_t dst_ip[NET_IP6_LEN];      // 目标IPv6地址
} ip6_hdr_t;
#pragma pack()

extern const uint8_t IPV4_MAPPED_PREFIX[NET_IP6_LEN];

// IPv6函数
void ip6_in(buf_t *buf, uint8_t *src_mac);
void ip6_out(buf_t *buf, uint8_t *ip6, net_protocol_t protocol);
void ip6_init();

// 地址转换函数
int ip4_to_ip6_addr(const uint8_t *ip4_addr, uint8_t *ip6_addr);
int ip6_to_ip4_addr(const uint8_t *ip6_addr, uint8_t *ip4_addr);
int is_ip4_mapped_ip6(const uint8_t *ip6_addr);

#endif