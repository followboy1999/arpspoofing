//ArpCheat.h 

#ifndef MY_ARP_CHEAT_INCLUDE_H 
#define MY_ARP_CHEAT_INCLUDE_H 

//�ֽڶ��������1 
#pragma pack (1) 
struct ethernet_head 
{ 
unsigned char dest_mac[6]; //Ŀ������MAC��ַ 
unsigned char source_mac[6]; //Դ��MAC��ַ 
unsigned short eh_type; //��̫������ 
}; 

struct arp_head 
{ 
unsigned short hardware_type; //Ӳ�����ͣ���̫���ӿ�����Ϊ1 
unsigned short protocol_type; //Э�����ͣ�IPЭ������Ϊ0X0800 
unsigned char add_len; //Ӳ����ַ���ȣ�MAC��ַ����Ϊ6B 
unsigned char pro_len; //Э���ַ���ȣ�IP��ַ����Ϊ4B 
unsigned short option; //������ARP����Ϊ1��ARPӦ��Ϊ2 
unsigned char sour_addr[6]; //ԴMAC��ַ�����ͷ���MAC��ַ 
unsigned long sour_ip; //ԴIP��ַ�����ͷ���IP��ַ 
unsigned char dest_addr[6]; //Ŀ��MAC��ַ��ARP�����и��ֶ�û�����壻ARP��Ӧ��Ϊ���շ���MAC��ַ 
unsigned long dest_ip; //Ŀ��IP��ַ��ARP������Ϊ���������IP��ַ��ARP��Ӧ��Ϊ���շ���IP��ַ 
unsigned char padding[18]; 
}; 

struct arp_packet //����arp���ṹ 
{ 
ethernet_head eth; //��̫��ͷ�� 
arp_head arp; //arp���ݰ�ͷ�� 
}; 

//Add by zjw
//////////////////////////////////////////////////////////////////////////////////
//start
struct IP_HEADER          //IPͷ�� 
{ 
    char m_ver_hlen;      //4λ�汾��,4λipͷ���� 
    char m_tos; 
    USHORT m_tlen; 
    USHORT m_ident; 
    USHORT m_flag_frag;     //3λ��־λ(1λδ��λ,1λDF,1λMF),13λƬ��ƫ���� 
    char m_ttl; 
    char m_protocol; 
    USHORT m_cksum; 
    ULONG m_sIP; 
    ULONG m_dIP; 
}; 

struct TCP_HEADER          //TCPͷ�� 
{ 
    USHORT m_sport; 
    USHORT m_dport; 
    ULONG m_seq; 
    ULONG m_ack;   
    char m_hlen_res4;              //4λtcpͷ����,6λ������ǰ4λ 
    char m_res2_flag;              //6λ�����ĺ�2λ,6λ��־ 
    USHORT m_win; 
    USHORT m_cksum; 
    USHORT m_urp; 
}; 

struct PSD_HEADER         //αͷ��������У����� 
{ 
    ULONG m_saddr; //Դ��ַ 
    ULONG m_daddr; //Ŀ�ĵ�ַ 
    char m_mbz; 
    char m_ptcl; //Э������ 
    USHORT m_tcpl; //TCP���� 
}; 

struct TCP_OPTION         //TCPѡ�����α����ʱҪ������Է�Э�� 
{ 
    USHORT unKnown; 
    USHORT maxSegSize;     //MSS,��̫��һ��Ϊ1460 
    char no1; 
    char no2; 
    USHORT SACK; 
}; 
//end
/////////////////////////////////////////////////////////////////////////////
#pragma pack () 
/** 
* ���������MAC��ַ 
* pDevName �������豸���� 
*/ 
unsigned char* GetSelfMac(char* pDevName); 
/** 
* ��װARP����� 
* source_mac ԴMAC��ַ 
* srcIP ԴIP 
* destIP Ŀ��IP 
*/ 
unsigned char* BuildArpPacket(unsigned char* source_mac, 

unsigned long srcIP, unsigned long destIP); 



#endif 
