#pragma once
#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17
#define ICMP_PROTOCOL 1
#define CHOOSE_HTTP 1
#define CHOOSE_ICMP 2
#define CHOOSE_DNS 3
#define ANYNOTCHOOSE -1
#define MacAddressLength 14
#define IP_TCPPacketHeaderLength 54
#define DNSPacketHeaderLength 54
#define ICMP_DATA_START_POINT 42
#define HTTP_PORT_NUMBER 80
#define DNS_PORT_NUMBER 53

#pragma comment (lib,"ws2_32.lib")
#pragma comment (lib,"Packet.lib")
#pragma comment (lib,"wpcap.lib")
#pragma warning(disable:4996)
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <WinSock2.h>

