#pragma once
#include <WinSock2.h>
/* 网络层协议类型 */
#define IP       0x0800
#define ARP      0x0806

/* 传输层类型 */
#define TRANS_ICMP       0x01
#define TRANS_TCP        0x06
#define TRANS_UDP        0x11

#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321

//mac帧类型定义
#define MAC_IP  0x0800
#define MAC_ARP 0x0806

/* 应用层类型 */
#define HTTP       0x50
#define DNS        0x35 

//Mac帧头 14字节
typedef struct eth_hdr
{
#if defined(LITTLE_ENDIAN)
    u_char dest[6];
    u_char src[6];
#elif defined(BIG_ENDIAN)
    u_char src[6];
    u_char dest[6];
#endif
    u_short type;
}eth_hdr;

//ARP头
typedef struct arp_hdr
{
#ifdef LITTLE_ENDIAN
    u_short ar_hrd : 8;
    u_short ar_unused : 8;
#elif defined(BIG_ENDIAN)
    u_short ar_unused : 8;
    u_short ar_hrd : 8;
#endif
    //u_short ar_hrd;						//硬件类型
    u_short ar_pro;						//协议类型
    u_char ar_hln;						//硬件地址长度
    u_char ar_pln;						//协议地址长度
    u_short ar_op;						//操作码，1为请求 2为回复
    u_char ar_srcmac[6];			    //发送方MAC
    u_char ar_srcip[4];				    //发送方IP
    u_char ar_destmac[6];			    //接收方MAC
    u_char ar_destip[4];  			//接收方IP
}arp_hdr;

//IPv4 首部 
typedef struct ip_hdr
{
#if defined(LITTLE_ENDIAN)
    u_char ip_ihl : 4;
    u_char ip_version : 4;
#elif defined(BIG_ENDIAN)
    u_char ip_version : 4;
    u_char  ip_ihl : 4;
#endif
    //u_char  ip_ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char  ip_tos;            // 服务类型(Type of service)
    u_short ip_tlen;           // 总长(Total length)
    u_short ip_id;              // 标识(Identification)
    u_short ip_flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量
                                //(Fragment offset) (13 bits)
    u_char  ip_ttl;            // 生存时间(Time to live)
    u_char  ip_type;           // 协议(Protocol)
    u_short ip_crc;            // 首部校验和(Header checksum)
    u_char ip_src[4];	      // 源地址(Source address)
    u_char ip_dest[4];       // 目的地址(Destination address)
    u_int   ip_op_pad;         // 选项与填充(Option + Padding)
}ip_hdr;

//TCP头部
typedef struct tcp_hdr
{
    u_short tcp_sport;			//源端口号
    u_short tcp_dport;			//目的端口号
    u_long tcp_seq;				//序列号
    u_long tcp_ack;				//确认号
#if defined(LITTLE_ENDIAN)
    u_short res1 : 4,
        doff : 4,
        fin : 1,
        syn : 1,
        rst : 1,
        psh : 1,
        ack : 1,
        urg : 1,
        ece : 1,
        cwr : 1;
#elif defined(BIG_ENDIAN)
    u_short doff : 4,
        res1 : 4,
        cwr : 1,
        ece : 1,
        urg : 1,
        ack : 1,
        psh : 1,
        rst : 1,
        syn : 1,
        fin : 1;
#endif
    u_short th_win;				//窗口大小
    u_short th_ckecksum;				//校验和
    u_short th_urp;				//紧急数据指针
}tcp_hdr;

//UDP头部
typedef struct udp_hdr
{
    u_short udp_sport;			//源端口号
    u_short udp_dport;			//目的端口号
    u_short udp_ulen;			//UDP数据报长度
    u_short udp_checksum;				//校验和
}udp_hdr;

//定义ICMP
typedef struct icmp_hdr
{
    u_char icmp_type;			//8位 类型
    u_char icmp_code;			//8位 代码
    u_char icmp_seq;				//序列号 8位
    u_char icmp_chksum;			//8位校验和
}icmp_hdr;

//DNS首部
typedef struct dns_hdr {
    u_short dns_id;             // 标识号
    u_short dns_flags;          // 标志
    u_short dns_qcount;         // 查询记录数
    u_short dns_ancount;        // 回答记录数
    u_short dns_nscount;        // 授权回答记录数
    u_short dns_arcount;        // 附加信息记录数
} DNSHDR, * pDNSHDR;

//计数结构体
typedef struct pktcount
{
    int n_ip;
    int n_arp;
    int n_tcp;
    int n_udp;
    int n_icmp;
    int n_dns;
    int n_sum;
};

//包结构体
typedef struct pkt_T
{
    char  pktType[8];					//包类型
    int time[6];						//时间
    int len;							//长度

    struct eth_hdr* eth_h;				//链路层包头

    struct arp_hdr* arp_h;				//ARP包头
    struct ip_hdr* ip_h;					//IP包头

    struct icmp_hdr* icmp_h;		//ICMP包头
    struct udp_hdr* udp_h;		//UDP包头
    struct tcp_hdr* tcp_h;		//TCP包头

    struct dns_hdr* dns_h;	//DNS包头

    void* app_hdr;							//应用层包头
    unsigned char data[65536];					//数据包内容
};