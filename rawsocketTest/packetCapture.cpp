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
// https://rookie24.tistory.com/2?category=796471 에서 코드를 따왔다.
int inputProtocal;
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
int checkHTTP(const struct pcap_pkthdr* header, const u_char* pkt_data);
void outputPacket(const struct pcap_pkthdr* header, const u_char* pkt_data);
int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    pcap_t* adhandle;
    int mode = 0; // pcap_open_live()사용시 모드
    int i = 0;
    int num = 0;
    char errbuf[PCAP_ERRBUF_SIZE];




    /* int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf) */
    // 네트워크 다비아스 목록을 가져온다.
    // alldevs에 List형태로 저장, 에러 발생시 errbuf에 에러 내용 저장
    // 성공 : 0            실패 : -1

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs : %s\n", errbuf);
        exit(1);
    }

    /* 네트워크 디바이스명 출력 */
    // Linked List 이므로 순차적으로 하나씩 검색
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    /* 디바이스가 하나도 없다면 */
    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    /* 캡쳐할 네트워크 디바이스 선택 */
    printf("Enter the interface number (1~%d) : ", i);
    scanf("%d", &num);
    printf("조사하고 싶은 프로토콜을 입력하세요. 1.HTTP, 2.ICMP, 3.DNS ");
    scanf("%d", &inputProtocal);
    /* 입력값의 유효성판단 */
    if (num < 1 || num > i)
    {
        printf("\nInterface number out of range\n");
        /* 장치  목록 해제 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* 사용자가 선택한 디바이스 선택 */
    // Single Linked List 이므로 처음부터 순회하여 선택한 걸 찾음
    for (d = alldevs, i = 0; i < num - 1; d = d->next, i++);


    /* 선택한 실제 네트워크 디바이스 오픈 */
    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* 장치 목록 해제 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    // 선택된 디바이스를 pcap_open_live로 열고 그것을 제어하기 위한 Handle을 받았으므로
    // 더 이상 그 디바이스에 대한 정보가 필요없다.
    // pcap_findalldevs를 통해 생성된 Linked List 삭제
    pcap_freealldevs(alldevs);

    /* 패킷 캡쳐 시작 */
    // 인자1 : pcap_open_live를 통해 얻은 네트워크 디바이스 핸들
    // 인자2 : 0=무한루프, 양의 정수=캡쳐할 패킷수
    // 인자3 : 패킷이 캡쳐되었을때, 호출될 함수 핸들러
    // 인자4 : 콜백함수로 넘겨줄 파라미터

    pcap_loop(adhandle, 0, packet_handler, NULL);


    /* 네트워크 디바이스 종료 */
    pcap_close(adhandle);

    return 0;
}

/* 패킷이 캡처 됬을때, 호출되는 콜백 함수 */
// 인자1 : 파라미터로 넘겨받은 값
// 인자2 : 패킷 정보
// 인자3 : 실제 캡처된 패킷 데이터
// 캡처한 패킷에 대한 모든 일은 이 함수 에서 
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    
    int i;
    int whatPacketIsIt;
    int isHTTPPacket = false;
    /*
    if (inputProtocal == 1) {       //TCP보는 코드
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
        //printf("확인할 수 없는 패킷입니다.");
    }
 
}
int checkHTTP(const struct pcap_pkthdr* header, const u_char* pkt_data) {
    //int IPTotalLength = pkt_data[16] * 256 + pkt_data[17] + MacAddressLength;    //아직은 사용하지 않는 변수이다.
    //TCP 패킷안에 HTTP 정보가 들어있는지 찾는 함수이다. 자세한건 와이어샤크 HTTP패킷 참조
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
void outputPacket(const struct pcap_pkthdr* header, const u_char* pkt_data) {       //수집한 패킷의 정보를 출력
    int i;
    for (i = 1; (i < header->caplen + 1); i++)
    {
        printf("%.2x ", pkt_data[i - 1]);
        if ((i % 16) == 0) printf("\n");
    }
    printf("\n\n");
}