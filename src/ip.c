#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"
#include <winsock2.h>

const uint8_t IPV4_MAPPED_PREFIX[NET_IP6_LEN] = {
    0x00, 0x00, 0x00, 0x00,  // 10字节的0
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0xff, 0xff,  // 0:0:0:0:0:0:FFFF:
    0x00, 0x00, 0x00, 0x00   // IPv4地址位置
};

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    // 检查数据包长度
    if (buf->len < sizeof(ip_hdr_t)) {
        return;
    }
    // 进行报头检测
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    if (ip_hdr->version != IP_VERSION_4 || 
        swap16(ip_hdr->total_len16) > buf->len) {
        return;
    }
    // 校验头部校验和
    uint16_t checksum = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    uint16_t calc_checksum = checksum16((uint16_t *)buf->data, sizeof(ip_hdr_t));
    if (checksum != calc_checksum) return;
    ip_hdr->hdr_checksum16 = checksum;
    
    // 对比目的 IP 地址
    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
        return;
    }

    // 去除填充字段
    if (buf->len > swap16(ip_hdr->total_len16)) {
        buf_remove_padding(buf, buf->len - swap16(ip_hdr->total_len16));
    }

    // 去掉 IP 报头
    buf_remove_header(buf, sizeof(ip_hdr_t));

    // 向上层传递数据包
    if (net_in(buf, ip_hdr->protocol, ip_hdr->src_ip) != 0) {
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO
    // 增加头部缓存空间
    buf_add_header(buf, sizeof(ip_hdr_t));

    // 填写头部字段
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = swap16(buf->len);
    ip_hdr->id16 = swap16(id);
    ip_hdr->flags_fragment16 = swap16((mf ? IP_MORE_FRAGMENT : 0) | offset);
    ip_hdr->ttl = IP_DEFALUT_TTL;
    ip_hdr->protocol = protocol;
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);

    // 计算并填写校验和
    ip_hdr->hdr_checksum16 = 0;
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)buf->data, sizeof(ip_hdr_t));

    // 发送数据
    arp_out(buf, ip);
}   

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
    // 检查数据报包长
    size_t max_payload = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    static int id = 0;

    if (buf->len <= max_payload) {
        // 直接发送
        ip_fragment_out(buf, ip, protocol, id, 0, 0);
    } else {
        // 分片处理
        uint16_t offset = 0;
        buf_t ip_buf;

        while (buf->len > 0) {
            size_t fragment_size = (buf->len > max_payload) ? max_payload : buf->len;

            buf_init(&ip_buf, fragment_size);
            memcpy(ip_buf.data, buf->data, fragment_size);

            ip_fragment_out(&ip_buf, ip, protocol, id, 
                            offset / IP_HDR_OFFSET_PER_BYTE, 
                            (buf->len > max_payload) ? 1 : 0);
            
            offset += fragment_size;
            buf->data += fragment_size;
            buf->len -= fragment_size;
        }
    }
    id++;

}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}

/**
 * @brief 处理一个收到的IPv6数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip6_in(buf_t *buf, uint8_t *src_mac) {
    if (buf->len < sizeof(ip6_hdr_t)) {
        return;
    }
    ip6_hdr_t *ip6_hdr = (ip6_hdr_t *)buf->data;

    // 检查版本
    uint8_t version = (ntohl(ip6_hdr->version_tc_flowlabel) >> 28) & 0xF;
    if (version != 6) {
        return;
    }

    // 检查有效载荷长度
    uint16_t payload_len = ntohs(ip6_hdr->payload_len);
    if (buf->len < sizeof(ip6_hdr_t) + payload_len) {
        return;
    }

    // 检查跳数限制
    if (ip6_hdr->hop_limit == 0) {
        return;
    }

    // 检查目的地址
    if (memcmp(ip6_hdr->dst_ip, net_if_ip6, NET_IP6_LEN) != 0) {
        uint8_t ipv4_addr[NET_IP_LEN];
        if (is_ip4_mapped_ip6(ip6_hdr->dst_ip) && 
            ip6_to_ip4_addr(ip6_hdr->dst_ip, ipv4_addr) &&
            memcmp(ipv4_addr, net_if_ip, NET_IP_LEN) == 0) {
            // 发给本机
        } else {
            return;
        }
    }

    buf_remove_header(buf, sizeof(ip6_hdr_t));

    uint8_t next_header = ip6_hdr->next_header;
    uint8_t src_ip6[NET_IP6_LEN];

    memcpy(src_ip6, ip6_hdr->src_ip, NET_IP6_LEN);
    if (net_in6(buf, next_header, src_ip6) < 0) {
        return;
    }
}

/**
 * @brief 处理一个要发送的IPv6数据包
 *
 * @param buf 要处理的包
 * @param ip6 目标IPv6地址
 * @param protocol 上层协议
 */
void ip6_out(buf_t *buf, uint8_t *ip6, net_protocol_t protocol) {
    int max_payload_len = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip6_hdr_t);
    if (buf->len > max_payload_len) {
        // 截断
        buf->len = max_payload_len;
    }

    uint16_t payload_len = buf->len;

    buf_add_header(buf, sizeof(ip6_hdr_t));
    ip6_hdr_t *ip6_hdr = (ip6_hdr_t *)buf->data;

    // 设置 IP 头部
    ip6_hdr->version_tc_flowlabel = htonl(IP_VERSION_6 << 28);
    ip6_hdr->payload_len = htons(payload_len);
    ip6_hdr->next_header = protocol;
    ip6_hdr->hop_limit = IP6_DEFAULT_HOP_LIMIT;
    memcpy(ip6_hdr->src_ip, net_if_ip6, NET_IP6_LEN);
    memcpy(ip6_hdr->dst_ip, ip6, NET_IP6_LEN);

#ifndef TEST
    uint8_t ipv4_addr[NET_IP_LEN];
    if (is_ip4_mapped_ip6(ip6) && ip6_to_ip4_addr(ip6, ipv4_addr)) {
        arp_out(buf, ipv4_addr);
    } else {
        ethernet_out(buf, ether_broadcast_mac, NET_PROTOCOL_IP6);
    }
#endif

}



/**
 * @brief 初始化IPv6协议
 */
void ip6_init() {
    net_add_protocol(NET_PROTOCOL_IP6, ip6_in);
}

/**
 * @brief 将IPv4地址转换为IPv4映射的IPv6地址
 * 
 * @param ip4_addr IPv4地址 (4字节)
 * @param ip6_addr 输出的IPv6地址 (16字节)
 * @return int 1表示成功，0表示失败
 */
int ip4_to_ip6_addr(const uint8_t *ip4_addr, uint8_t *ip6_addr) {
    if (!ip4_addr || !ip6_addr) {
        return 0;
    }
    // 填充IPv4映射前缀
    memcpy(ip6_addr, IPV4_MAPPED_PREFIX, NET_IP6_LEN);
    
    // 复制IPv4地址到最后4个字节
    memcpy(ip6_addr + 12, ip4_addr, NET_IP_LEN);
    return 1;
}

/**
 * @brief 检查IPv6地址是否是IPv4映射地址
 * 
 * @param ip6_addr IPv6地址 (16字节)
 * @return int 1表示是IPv4映射地址，0表示不是
 */
int is_ip4_mapped_ip6(const uint8_t *ip6_addr) {
    if (!ip6_addr) {
        return 0;
    }
    
    // 检查前 10 个字节是否为 0
    for (int i = 0; i < 10; i++) {
        if (ip6_addr[i] != 0) {
            return 0;
        }
    }
    // 检查第 11、12 个字节是否为 0xFF
    if (ip6_addr[10] != 0xFF || ip6_addr[11] != 0xFF) {
        return 0;
    }
    
    return 1;
}

/**
 * @brief 从IPv4映射的IPv6地址中提取IPv4地址
 * 
 * @param ip6_addr IPv6地址 (16字节)
 * @param ip4_addr 输出的IPv4地址 (4字节)
 * @return int 1表示成功，0表示失败或不是IPv4映射地址
 */
int ip6_to_ip4_addr(const uint8_t *ip6_addr, uint8_t *ip4_addr) {
    if (!ip6_addr || !ip4_addr) {
        return 0;
    }
    // 检查是否是IPv4映射地址
    if (!is_ip4_mapped_ip6(ip6_addr)) {
        return 0;
    }
    // 提取IPv4地址
    memcpy(ip4_addr, ip6_addr + 12, NET_IP_LEN);
    return 1;
}
