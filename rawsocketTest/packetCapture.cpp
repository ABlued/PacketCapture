#pragma comment (lib,"ws2_32.lib")
#pragma comment (lib,"Packet.lib")
#pragma comment (lib,"wpcap.lib")
#pragma warning(disable:4996)
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <WinSock2.h>
#include "define.h"
#include "struct.h"
// https://rookie24.tistory.com/2?category=796471 ���� �ڵ带 ���Դ�.
int inputProtocal;
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
int checkHTTP(const struct pcap_pkthdr* header, const u_char* pkt_data);
void outputPacket(const struct pcap_pkthdr* header, const u_char* pkt_data);
int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    pcap_t* adhandle;
    int mode = 0; // pcap_open_live()���� ���
    int i = 0;
    int num = 0;
    char errbuf[PCAP_ERRBUF_SIZE];




    /* int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf) */
    // ��Ʈ��ũ �ٺ�ƽ� ����� �����´�.
    // alldevs�� List���·� ����, ���� �߻��� errbuf�� ���� ���� ����
    // ���� : 0            ���� : -1

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs : %s\n", errbuf);
        exit(1);
    }

    /* ��Ʈ��ũ ����̽��� ��� */
    // Linked List �̹Ƿ� ���������� �ϳ��� �˻�
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    /* ����̽��� �ϳ��� ���ٸ� */
    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    /* ĸ���� ��Ʈ��ũ ����̽� ���� */
    printf("Enter the interface number (1~%d) : ", i);
    scanf("%d", &num);
    printf("�����ϰ� ���� ���������� �Է��ϼ���. 1.HTTP, 2.ICMP, 3.DNS ");
    scanf("%d", &inputProtocal);
    /* �Է°��� ��ȿ���Ǵ� */
    if (num < 1 || num > i)
    {
        printf("\nInterface number out of range\n");
        /* ��ġ  ��� ���� */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* ����ڰ� ������ ����̽� ���� */
    // Single Linked List �̹Ƿ� ó������ ��ȸ�Ͽ� ������ �� ã��
    for (d = alldevs, i = 0; i < num - 1; d = d->next, i++);


    /* ������ ���� ��Ʈ��ũ ����̽� ���� */
    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* ��ġ ��� ���� */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    // ���õ� ����̽��� pcap_open_live�� ���� �װ��� �����ϱ� ���� Handle�� �޾����Ƿ�
    // �� �̻� �� ����̽��� ���� ������ �ʿ����.
    // pcap_findalldevs�� ���� ������ Linked List ����
    pcap_freealldevs(alldevs);

    /* ��Ŷ ĸ�� ���� */
    // ����1 : pcap_open_live�� ���� ���� ��Ʈ��ũ ����̽� �ڵ�
    // ����2 : 0=���ѷ���, ���� ����=ĸ���� ��Ŷ��
    // ����3 : ��Ŷ�� ĸ�ĵǾ�����, ȣ��� �Լ� �ڵ鷯
    // ����4 : �ݹ��Լ��� �Ѱ��� �Ķ����

    pcap_loop(adhandle, 0, packet_handler, NULL);


    /* ��Ʈ��ũ ����̽� ���� */
    pcap_close(adhandle);

    return 0;
}

/* ��Ŷ�� ĸó ������, ȣ��Ǵ� �ݹ� �Լ� */
// ����1 : �Ķ���ͷ� �Ѱܹ��� ��
// ����2 : ��Ŷ ����
// ����3 : ���� ĸó�� ��Ŷ ������
// ĸó�� ��Ŷ�� ���� ��� ���� �� �Լ� ���� 
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    
    int i;
    int whatPacketIsIt;
    int isHTTPPacket = false;
    /*
    if (inputProtocal == 1) {       //TCP���� �ڵ�
        if (pkt_data[23] == TCP_PROTOCOL) {
            isTCPPacket = true;
            TCP_HDR* currentTCP = (tcp_hdr*)malloc(sizeof(tcp_hdr));
            TCP* TCPClass = new TCP(currentTCP);
            TCPClass->makeTCPPacket(pkt_data);
            //outputPacket(header, pkt_data);
            TCPClass->printTCP();
            free(currentTCP);
            delete TCPClass;
        }
        else isTCPPacket = false;
    }*/
    if (inputProtocal == 1) {
        if (pkt_data[23] == TCP_PROTOCOL) whatPacketIsIt = TCP_PROTOCOL;
        else if (pkt_data[23] == UDP_PROTOCOL) whatPacketIsIt = UDP_PROTOCOL;
        else whatPacketIsIt = false;
    }

    switch (whatPacketIsIt) {
    case TCP_PROTOCOL:        
        isHTTPPacket = checkHTTP(header, pkt_data);
       
        if (isHTTPPacket == true) {
            IPV4_HDR* currentIP = (ip_hdr*)malloc(sizeof(struct ip_hdr));
            IP* IPClass = new IP(currentIP);
            IPClass->makeIPPacket(pkt_data);

            TCP_HDR* currentTCP = (tcp_hdr*)malloc(sizeof(tcp_hdr));
            TCP* TCPClass = new TCP(currentTCP);
            TCPClass->makeTCPPacket(pkt_data);

            IPClass->printIP();
            TCPClass->printTCP();


            delete TCPClass;
            delete IPClass;
        }
        break;
    case UDP_PROTOCOL: {

            IPV4_HDR* currentIP = (ip_hdr*)malloc(sizeof(struct ip_hdr));
            IP* IPClass = new IP(currentIP);
            IPClass->makeIPPacket(pkt_data);

            UDP_HDR* currentUDP = (udp_hdr*)malloc(sizeof(udp_hdr));
            UDP* UDPClass = new UDP(currentUDP);
            UDPClass->makeUDPPacket(pkt_data);

            IPClass->printIP();
            UDPClass->printUDP();


            delete UDPClass;
            delete IPClass;
            break;
    }

    case false :

        break;
        //printf("Ȯ���� �� ���� ��Ŷ�Դϴ�.");
    }
 
}
int checkHTTP(const struct pcap_pkthdr* header, const u_char* pkt_data) {
    //int IPTotalLength = pkt_data[16] * 256 + pkt_data[17] + MacAddressLength;    //������ ������� �ʴ� �����̴�.
    //TCP ��Ŷ�ȿ� HTTP ������ ����ִ��� ã�� �Լ��̴�. �ڼ��Ѱ� ���̾��ũ HTTP��Ŷ ����
    for (int i = 0; i < header->caplen; i++)
    {
        if (pkt_data[i] == HTTP_PROTOCOL_1)
            if (pkt_data[i + 1] == HTTP_PROTOCOL_2 &&
                pkt_data[i + 2] == HTTP_PROTOCOL_3 &&
                pkt_data[i + 3] == HTTP_PROTOCOL_4
                ) {
                return true;
            }

    }
    return false;
}
void outputPacket(const struct pcap_pkthdr* header, const u_char* pkt_data) {       //������ ��Ŷ�� ������ ���
    int i;
    for (i = 1; (i < header->caplen + 1); i++)
    {
        printf("%.2x ", pkt_data[i - 1]);
        if ((i % 16) == 0) printf("\n");
    }
    printf("\n\n");
}