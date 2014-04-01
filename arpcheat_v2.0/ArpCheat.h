//ArpCheat.h 

#ifndef MY_ARP_CHEAT_INCLUDE_H 
#define MY_ARP_CHEAT_INCLUDE_H 

//字节对齐必须是1 
#pragma pack (1) 
struct ethernet_head 
{ 
unsigned char dest_mac[6]; //目标主机MAC地址 
unsigned char source_mac[6]; //源端MAC地址 
unsigned short eh_type; //以太网类型 
}; 

struct arp_head 
{ 
unsigned short hardware_type; //硬件类型：以太网接口类型为1 
unsigned short protocol_type; //协议类型：IP协议类型为0X0800 
unsigned char add_len; //硬件地址长度：MAC地址长度为6B 
unsigned char pro_len; //协议地址长度：IP地址长度为4B 
unsigned short option; //操作：ARP请求为1，ARP应答为2 
unsigned char sour_addr[6]; //源MAC地址：发送方的MAC地址 
unsigned long sour_ip; //源IP地址：发送方的IP地址 
unsigned char dest_addr[6]; //目的MAC地址：ARP请求中该字段没有意义；ARP响应中为接收方的MAC地址 
unsigned long dest_ip; //目的IP地址：ARP请求中为请求解析的IP地址；ARP响应中为接收方的IP地址 
unsigned char padding[18]; 
}; 

struct arp_packet //最终arp包结构 
{ 
ethernet_head eth; //以太网头部 
arp_head arp; //arp数据包头部 
}; 

//Add by zjw
//////////////////////////////////////////////////////////////////////////////////
//start
struct IP_HEADER          //IP头部 
{ 
    char m_ver_hlen;      //4位版本号,4位ip头部长 
    char m_tos; 
    USHORT m_tlen; 
    USHORT m_ident; 
    USHORT m_flag_frag;     //3位标志位(1位未用位,1位DF,1位MF),13位片断偏移量 
    char m_ttl; 
    char m_protocol; 
    USHORT m_cksum; 
    ULONG m_sIP; 
    ULONG m_dIP; 
}; 

struct TCP_HEADER          //TCP头部 
{ 
    USHORT m_sport; 
    USHORT m_dport; 
    ULONG m_seq; 
    ULONG m_ack;   
    char m_hlen_res4;              //4位tcp头部长,6位保留的前4位 
    char m_res2_flag;              //6位保留的后2位,6位标志 
    USHORT m_win; 
    USHORT m_cksum; 
    USHORT m_urp; 
}; 

struct PSD_HEADER         //伪头部，计算校验和用 
{ 
    ULONG m_saddr; //源地址 
    ULONG m_daddr; //目的地址 
    char m_mbz; 
    char m_ptcl; //协议类型 
    USHORT m_tcpl; //TCP长度 
}; 

struct TCP_OPTION         //TCP选项，发起伪连接时要用来与对方协商 
{ 
    USHORT unKnown; 
    USHORT maxSegSize;     //MSS,以太网一般为1460 
    char no1; 
    char no2; 
    USHORT SACK; 
}; 
//end
/////////////////////////////////////////////////////////////////////////////
#pragma pack () 
/** 
* 获得网卡的MAC地址 
* pDevName 网卡的设备名称 
*/ 
unsigned char* GetSelfMac(char* pDevName); 
/** 
* 封装ARP请求包 
* source_mac 源MAC地址 
* srcIP 源IP 
* destIP 目的IP 
*/ 
unsigned char* BuildArpPacket(unsigned char* source_mac, 

unsigned long srcIP, unsigned long destIP); 



#endif 
