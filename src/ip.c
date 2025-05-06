#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

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
        return;
    }

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

    id++;

}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}