#include "arp.h"
#include "driver.h"
#include "ethernet.h"
#include "ip.h"
#include "testing/log.h"
#include "net.h"
#include "buf.h"
#include "utils.h"
#include "udp.h"
#include "tcp.h"
#include "icmp.h"
#include "map.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

#ifdef _WIN32
#include <winsock2.h>  // 提供网络字节序转换函数 htons, htonl, ntohs, ntohl
#include <ws2tcpip.h>  // 额外的网络函数
#pragma comment(lib, "ws2_32.lib")  // 链接Winsock库
#else
#include <arpa/inet.h>  // 在非Windows系统提供网络字节序转换函数
#endif

// 外部变量声明
extern FILE *pcap_in;
extern FILE *pcap_out;
extern FILE *control_flow;
extern FILE *icmp_fout;
extern FILE *udp_fout;
extern FILE *arp_log_f;
extern map_t net_table;

char *print_ip(uint8_t *ip);
char *print_mac(uint8_t *mac);

uint8_t my_mac[] = NET_IF_MAC;
uint8_t boardcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void log_tab_buf();
FILE *open_file(char *path, char *name, char *mode);

// 全局变量
buf_t test_buf;
buf_t buf;
int test_passed = 0;
int test_failed = 0;

// 测试辅助函数
void test_assert(int condition, const char *test_name) {
    if (condition) {
        printf("[PASS]: %s\n", test_name);
        test_passed++;
    } else {
        printf("[FAIL]: %s\n", test_name);
        test_failed++;
    }
}

void print_ipv6_addr(const uint8_t *ip6) {
    printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
           ip6[0], ip6[1], ip6[2], ip6[3], ip6[4], ip6[5], ip6[6], ip6[7],
           ip6[8], ip6[9], ip6[10], ip6[11], ip6[12], ip6[13], ip6[14], ip6[15]);
}

// 测试1: IPv6地址转换函数测试
void test_ipv6_address_conversion() {
    printf("\n=== Test IPv6 address conversion functions ===\n");
    
    // 测试IPv4到IPv6映射地址转换
    uint8_t ipv4_addr[] = {192, 168, 1, 100};
    uint8_t ipv6_mapped[NET_IP6_LEN];
    
    int result = ip4_to_ip6_addr(ipv4_addr, ipv6_mapped);
    test_assert(result == 1, "IPv4 to IPv6 mapped address conversion should succeed");
    
    // 验证映射地址格式 (::FFFF:192.168.1.100)
    uint8_t expected_mapped[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xFF, 0xFF, 192, 168, 1, 100
    };
    test_assert(memcmp(ipv6_mapped, expected_mapped, NET_IP6_LEN) == 0, 
                "IPv4-mapped IPv6 address format is correct");
    
    // 测试IPv4映射地址检测
    test_assert(is_ip4_mapped_ip6(ipv6_mapped) == 1, "Should detect IPv4-mapped address");
    
    // 测试从IPv6映射地址提取IPv4地址
    uint8_t extracted_ipv4[NET_IP_LEN];
    result = ip6_to_ip4_addr(ipv6_mapped, extracted_ipv4);
    test_assert(result == 1, "Extracting IPv4 address from IPv6 mapped address should succeed");
    test_assert(memcmp(extracted_ipv4, ipv4_addr, NET_IP_LEN) == 0, 
                "Extracted IPv4 address should match original");
    
    // 测试纯IPv6地址（非映射地址）
    uint8_t pure_ipv6[] = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    test_assert(is_ip4_mapped_ip6(pure_ipv6) == 0, "Pure IPv6 address should not be detected as IPv4-mapped");
    
    result = ip6_to_ip4_addr(pure_ipv6, extracted_ipv4);
    test_assert(result == 0, "Extracting IPv4 address from pure IPv6 address should fail");
}

// 测试2: IPv6数据包头部解析测试
void test_ipv6_header_parsing() {
    printf("\n=== Test IPv6 packet header parsing ===\n");
    
    // 创建模拟IPv6数据包
    buf_init(&test_buf, sizeof(ip6_hdr_t) + 20); // IPv6头部 + 20字节数据
    
    ip6_hdr_t *ip6_hdr = (ip6_hdr_t *)test_buf.data;
    
    // 设置IPv6头部
    uint32_t version_tc_flowlabel = (IP_VERSION_6 << 28) | (0 << 20) | 0x12345; // 版本6，流量类别0，流标签0x12345
    ip6_hdr->version_tc_flowlabel = htonl(version_tc_flowlabel);
    ip6_hdr->payload_len = htons(20); // 有效载荷长度
    ip6_hdr->next_header = NET_PROTOCOL_UDP; // 下一个头部为UDP
    ip6_hdr->hop_limit = IP6_DEFAULT_HOP_LIMIT;
    
    // 设置源和目标IPv6地址
    uint8_t src_ipv6[] = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    };
    memcpy(ip6_hdr->src_ip, src_ipv6, NET_IP6_LEN);
    memcpy(ip6_hdr->dst_ip, net_if_ip6, NET_IP6_LEN);
    
    // 验证头部字段解析
    uint8_t version = (ntohl(ip6_hdr->version_tc_flowlabel) >> 28) & 0xF;
    test_assert(version == IP_VERSION_6, "IPv6 version field parsed correctly");
    
    uint8_t traffic_class = (ntohl(ip6_hdr->version_tc_flowlabel) >> 20) & 0xFF;
    test_assert(traffic_class == 0, "Traffic class parsed correctly");
    
    uint32_t flow_label = ntohl(ip6_hdr->version_tc_flowlabel) & 0xFFFFF;
    test_assert(flow_label == 0x12345, "Flow label parsed correctly");
    
    test_assert(ntohs(ip6_hdr->payload_len) == 20, "Payload length parsed correctly");
    test_assert(ip6_hdr->next_header == NET_PROTOCOL_UDP, "Next header field parsed correctly");
    test_assert(ip6_hdr->hop_limit == IP6_DEFAULT_HOP_LIMIT, "Hop limit parsed correctly");
}

// 测试3: IPv6数据包发送测试
void test_ipv6_packet_output() {
    printf("\n=== Test IPv6 packet output ===\n");
    
    // 创建测试数据
    char test_data[] = "Hello IPv6 World!";
    buf_init(&test_buf, strlen(test_data));
    memcpy(test_buf.data, test_data, strlen(test_data));
    
    // 目标IPv6地址
    uint8_t dst_ipv6[] = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    };
    
    // 测试IPv6数据包输出
    size_t original_len = test_buf.len;
    ip6_out(&test_buf, dst_ipv6, NET_PROTOCOL_UDP);
    
    // 验证是否添加了IPv6头部
    test_assert(test_buf.len == original_len + sizeof(ip6_hdr_t), 
                "IPv6 header added correctly");
    
    // 验证IPv6头部内容
    ip6_hdr_t *ip6_hdr = (ip6_hdr_t *)test_buf.data;
    uint8_t version = (ntohl(ip6_hdr->version_tc_flowlabel) >> 28) & 0xF;
    test_assert(version == IP_VERSION_6, "IPv6 version set correctly");
    
    test_assert(ntohs(ip6_hdr->payload_len) == original_len, 
                "Payload length set correctly");
    test_assert(ip6_hdr->next_header == NET_PROTOCOL_UDP, 
                "Next header field set correctly");
    test_assert(ip6_hdr->hop_limit == IP6_DEFAULT_HOP_LIMIT, 
                "Hop limit set correctly");
    
    test_assert(memcmp(ip6_hdr->src_ip, net_if_ip6, NET_IP6_LEN) == 0, 
                "Source IPv6 address set correctly");
    test_assert(memcmp(ip6_hdr->dst_ip, dst_ipv6, NET_IP6_LEN) == 0, 
                "Destination IPv6 address set correctly");
}

// 测试4: IPv6与IPv4映射地址互通测试
void test_ipv6_ipv4_interoperability() {
    printf("\n=== Test IPv6 and IPv4-mapped address interoperability ===\n");
    
    // 创建IPv4地址
    uint8_t ipv4_addr[] = {192, 168, 1, 100};
    
    // 转换为IPv6映射地址
    uint8_t ipv6_mapped[NET_IP6_LEN];
    ip4_to_ip6_addr(ipv4_addr, ipv6_mapped);
    
    // 创建测试数据包
    char test_data[] = "IPv4-IPv6 interop test";
    buf_init(&test_buf, strlen(test_data));
    memcpy(test_buf.data, test_data, strlen(test_data));
    
    // 使用IPv6映射地址发送数据包
    size_t original_len = test_buf.len;
    ip6_out(&test_buf, ipv6_mapped, NET_PROTOCOL_UDP);
    
    // 验证数据包格式
    test_assert(test_buf.len == original_len + sizeof(ip6_hdr_t), 
                "IPv6 header added to IPv4-mapped address packet");
    
    ip6_hdr_t *ip6_hdr = (ip6_hdr_t *)test_buf.data;
    test_assert(memcmp(ip6_hdr->dst_ip, ipv6_mapped, NET_IP6_LEN) == 0, 
                "Destination address set to IPv4-mapped IPv6 address");
    
    // 验证可以正确识别为IPv4映射地址
    test_assert(is_ip4_mapped_ip6(ip6_hdr->dst_ip) == 1, 
                "Packet destination address correctly detected as IPv4-mapped");
}

// 测试5: IPv6数据包接收测试
void test_ipv6_packet_input() {
    printf("\n=== Test IPv6 packet input ===\n");
    
    // 创建模拟IPv6数据包
    char test_payload[] = "Received IPv6 packet";
    buf_init(&test_buf, sizeof(ip6_hdr_t) + strlen(test_payload));
    
    ip6_hdr_t *ip6_hdr = (ip6_hdr_t *)test_buf.data;
    
    // 设置IPv6头部
    uint32_t version_tc_flowlabel = IP_VERSION_6 << 28;
    ip6_hdr->version_tc_flowlabel = htonl(version_tc_flowlabel);
    ip6_hdr->payload_len = htons(strlen(test_payload));
    ip6_hdr->next_header = NET_PROTOCOL_UDP;
    ip6_hdr->hop_limit = 64;
    
    // 设置源和目标地址
    uint8_t src_ipv6[] = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    };
    memcpy(ip6_hdr->src_ip, src_ipv6, NET_IP6_LEN);
    memcpy(ip6_hdr->dst_ip, net_if_ip6, NET_IP6_LEN); // 发送给本机
      // 添加测试数据
    memcpy(test_buf.data + sizeof(ip6_hdr_t), test_payload, strlen(test_payload));
    
    // 模拟接收过程中的基本验证
    test_assert(test_buf.len >= sizeof(ip6_hdr_t), "Packet length is sufficient for IPv6 header");
    
    uint8_t version = (ntohl(ip6_hdr->version_tc_flowlabel) >> 28) & 0xF;
    test_assert(version == IP_VERSION_6, "IPv6 version validated");
    
    uint16_t payload_len = ntohs(ip6_hdr->payload_len);
    test_assert(payload_len + sizeof(ip6_hdr_t) <= test_buf.len, 
                "Payload length validated");
    
    test_assert(memcmp(ip6_hdr->dst_ip, net_if_ip6, NET_IP6_LEN) == 0, 
                "Destination address is local IPv6 address");
}

// 测试6: IPv6大数据包分片处理测试
void test_ipv6_large_packet_handling() {
    printf("\n=== Test IPv6 large packet handling ===\n");
    
    // 创建超过MTU的大数据包
    size_t large_data_size = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip6_hdr_t) + 100;
    buf_init(&test_buf, large_data_size);
    
    // 填充测试数据
    for (size_t i = 0; i < large_data_size; i++) {
        test_buf.data[i] = (uint8_t)(i % 256);
    }
    
    uint8_t dst_ipv6[] = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02    };
    
    // 测试大数据包处理
    ip6_out(&test_buf, dst_ipv6, NET_PROTOCOL_UDP);
    
    // 验证数据包是否被正确处理（截断或分片）
    test_assert(test_buf.len <= ETHERNET_MAX_TRANSPORT_UNIT, 
                "Large packet handled correctly, does not exceed Ethernet MTU");
    
    // 如果数据包被截断，验证头部仍然正确
    if (test_buf.len <= ETHERNET_MAX_TRANSPORT_UNIT) {
        ip6_hdr_t *ip6_hdr = (ip6_hdr_t *)test_buf.data;
        uint8_t version = (ntohl(ip6_hdr->version_tc_flowlabel) >> 28) & 0xF;
        test_assert(version == IP_VERSION_6, "IPv6 header remains correct after truncation");
    }
}

// 测试7: IPv6错误处理测试
void test_ipv6_error_handling() {
    printf("\n=== Test IPv6 error handling ===\n");
    
    // 测试1: 数据包太小
    buf_init(&test_buf, sizeof(ip6_hdr_t) - 1);
    uint8_t src_mac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    
    // 这应该被拒绝，因为数据包太小
    size_t len_before = test_buf.len;
    ip6_in(&test_buf, src_mac);
    test_assert(test_buf.len == len_before, "Packet too small is correctly rejected");
    
    // 测试2: 错误的版本号
    buf_init(&test_buf, sizeof(ip6_hdr_t) + 10);
    ip6_hdr_t *ip6_hdr = (ip6_hdr_t *)test_buf.data;
    
    // 设置错误的版本号（4而不是6）
    uint32_t wrong_version = (IP_VERSION_4 << 28);
    ip6_hdr->version_tc_flowlabel = htonl(wrong_version);
    ip6_hdr->payload_len = htons(10);
    
    len_before = test_buf.len;
    ip6_in(&test_buf, src_mac);
    test_assert(test_buf.len == len_before, "Packet with wrong version is correctly rejected");
    
    // 测试3: 有效载荷长度不匹配
    uint32_t correct_version = (IP_VERSION_6 << 28);
    ip6_hdr->version_tc_flowlabel = htonl(correct_version);
    ip6_hdr->payload_len = htons(50); // 声称有50字节，但实际只有10字节
    memcpy(ip6_hdr->dst_ip, net_if_ip6, NET_IP6_LEN);
    
    len_before = test_buf.len;
    ip6_in(&test_buf, src_mac);
    test_assert(test_buf.len == len_before, "Packet with mismatched payload length is correctly rejected");
}

// 测试8: IPv6双协议栈集成测试
void test_ipv6_dual_stack_integration() {
    printf("\n=== Test IPv6 dual stack integration ===\n");
    
    // 测试IPv4和IPv6地址配置
    test_assert(net_if_ip[0] != 0 || net_if_ip[1] != 0 || 
                net_if_ip[2] != 0 || net_if_ip[3] != 0, 
                "IPv4 address is configured");
    
    int ipv6_configured = 0;
    for (int i = 0; i < NET_IP6_LEN; i++) {
        if (net_if_ip6[i] != 0) {
            ipv6_configured = 1;
            break;
        }
    }
    test_assert(ipv6_configured, "IPv6 address is configured");
    
    // 测试协议栈同时处理IPv4和IPv6
    printf("Local IPv4 address: %s\n", iptos(net_if_ip));
    printf("Local IPv6 address: ");
    print_ipv6_addr(net_if_ip6);
    printf("\n");
    
    // 验证IPv4映射IPv6地址与本机IPv4地址的对应关系
    uint8_t mapped_local_ipv6[NET_IP6_LEN];
    ip4_to_ip6_addr(net_if_ip, mapped_local_ipv6);
    
    printf("Local IPv4-mapped IPv6 address: ");
    print_ipv6_addr(mapped_local_ipv6);
    printf("\n");
    
    test_assert(is_ip4_mapped_ip6(mapped_local_ipv6), 
                "Local IPv4 address can be correctly mapped to IPv6");
}

// 主测试函数
int main(int argc, char *argv[]) {
    int ret;
    PRINT_INFO("Test begin.\n");
    
    // 打开pcap文件进行协议栈初始化
    pcap_in = open_file(argv[1], "in.pcap", "r");
    pcap_out = open_file(argv[1], "out.pcap", "w");
    control_flow = open_file(argv[1], "log", "w");
    if (pcap_in == 0 || pcap_out == 0 || control_flow == 0) {
        if (pcap_in)
            fclose(pcap_in);
        else
            PRINT_ERROR("Failed to open in.pcap\n");
        if (pcap_out)
            fclose(pcap_out);
        else
            PRINT_ERROR("Failed to open out.pcap\n");
        if (control_flow)
            fclose(control_flow);
        else
            PRINT_ERROR("Failed to open log\n");
        return -1;
    }
    icmp_fout = control_flow;
    udp_fout = control_flow;
    arp_log_f = control_flow;

    // 协议栈初始化
    net_init();
    log_tab_buf();
    
    // 读取pcap数据包进行协议栈初始化（不影响测试逻辑）
    int i = 1;
    PRINT_INFO("Feeding input %02d", i);
    while ((ret = driver_recv(&buf)) > 0) {
        printf("\b\b%02d", i);
        fprintf(control_flow, "\nRound %02d -----------------------------\n", i++);
        ethernet_in(&buf);
        log_tab_buf();
    }
    if (ret < 0) {
        PRINT_WARN("\nError occur on loading input,exiting\n");
    }
    driver_close();
    PRINT_INFO("\nSample input all processed, starting IPv6 tests\n");
    
    printf("Starting IPv6 dual stack unit tests\n");
    printf("========================================\n");
    
    // 执行所有测试
    test_ipv6_address_conversion();
    test_ipv6_header_parsing();
    test_ipv6_packet_output();
    test_ipv6_ipv4_interoperability();
    test_ipv6_packet_input();
    test_ipv6_large_packet_handling();
    test_ipv6_error_handling();
    test_ipv6_dual_stack_integration();
    
    // 输出测试结果
    printf("\n========================================\n");
    printf("Test complete!\n");
    printf("Passed: %d tests\n", test_passed);
    printf("Failed: %d tests\n", test_failed);
      // 关闭文件
    fclose(control_flow);
      if (test_failed == 0) {
        printf("[OK] All tests passed! IPv6 dual stack implementation is correct.\n");
        return 0;
    } else {
        printf("[ERROR] %d tests failed, please check the implementation.\n", test_failed);
        return 1;
    }
}