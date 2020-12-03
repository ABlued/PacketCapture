#pragma once
#include <iostream>
typedef struct ip_hdr
{
    unsigned char  version;            // 4-bit IPv4 version
    unsigned char  headerLength;       // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
    unsigned char  typeOfService;          // IP type of service
    unsigned short totalLength;            // Total length
    unsigned short identification;         // Unique identifier 
    unsigned char  fragOffset;         // Fragment offset field
    unsigned char  moreFragment;
    unsigned char  dontFragment;
    unsigned char  reservedZero;
    unsigned char  fragOffset1;           // fragment offset
    unsigned char  TTL;                   // Time to live
    unsigned char  protocolType;          // Protocol(TCP,UDP etc)
    unsigned short checkSum;              // IP checksum
    unsigned char   sourceAddress[4];         // Source address
    unsigned char   destinationAddress[4];    // Destination address
} IPV4_HDR;
class IP {
private:
	IPV4_HDR* ipHeader;
public:
	IP(IPV4_HDR* ipHeader);
	void makeIPPacket(const unsigned char* pkt_data);
	void setVersion(char version);
	void setHeaderLength(char headerLength);
	void setTypeOfService(char typeOfService);
	void setTotalLength(short totalLength);
	void setIdentification(short identification);
	void setFragOffset(char fragOffset);
	void setMoreFragment(char moreFragment);
	void setDontFragment(char dontFragment);
	void setReservedZero(char reservedZero);
	void setFragOffset1(char fragOffset1);
	void setTTL(char TTL);
	void setProtocolType(char protocolType);
	void setCheckSum(short checkSum);
	void setSourceAddress(char sourceAddress, int index);
	void setDestinationAddress(char destinationAddress, int index);


	unsigned char getVersion();
	unsigned char getHeaderLength();
	unsigned char getTypeOfService();
	unsigned short getTotalLength();
	unsigned short getIdentification();
	unsigned char getFragOffset();
	unsigned char getMoreFragment();
	unsigned char getDontFragment();
	unsigned char getReservedZero();
	unsigned char getFragOffset1();
	unsigned char getTTL();
	unsigned char  getProtocolType();
	unsigned short getCheckSum();
	unsigned char  getSourceAddress(int index);
	unsigned char  getDestinationAddress(int index);

	void printIP();
};
typedef struct tcp_hdr 
{
	unsigned short sourcePort;		// source port - 16 bit
	unsigned short destPort;		// destination port - 16bit
	unsigned int sequenceNumber;	// sequence number - 32 bit
	unsigned int acknowledgeNumber; // acknowledgement number - 32 bit
	
	unsigned char dataOffset; /*The number of 32-bit words in the TCP header.
								  This indicates where the data begins.
								  The length of the TCP header is always a multiple
								  of 32 bits.*/
	
/*	unsigned char res : 3; // According to rfc					
	unsigned char ns : 1;  // Nonce Sum Flag Added in RFC 3540. (새롭게 생긴 비트)
	unsigned char cwr : 1; // Congestion Window Reduced Flag	(새롭게 생긴 비트)
	unsigned char ecn : 1; // ECN-Echo Flag						(새롭게 생긴 비트)
	unsigned char urg : 1; // Urgent Flag
	unsigned char ack : 1; // Acknowledgement Flag
	unsigned char psh : 1; // Push Flag
	unsigned char rst : 1; // Reset Flag
	unsigned char syn : 1; // Synchronise Flag
	unsigned char fin : 1; // Finish Flag*/
	
	unsigned short windowSize;    // window
	unsigned short checkSum;	  // checksum
	unsigned short urgentPointer; // urgent pointer

} TCP_HDR;
class TCP{
private:
	TCP_HDR* tcpHeader;
public:
	TCP(TCP_HDR* tcpHeader);
	void makeTCPPacket(const unsigned char* pkt_data);
	void setSourcePort(short sourcePort);
	void setDestPort(short DestPort);
	void setSequenceNumber(unsigned int sequenceNumber);
	void setAcknowledgeNumber(unsigned int acknowledgeNumber);
	void setDataOffset(char dataOffset);
	void setWindowSize(short windowSize);
	void setCheckSum(short checkSum);

	unsigned short getSourcePort();
	unsigned short getDestPort();
	unsigned int getSequenceNumber();
	unsigned int getAcknowledgeNumber();
	unsigned char getDataOffset();
	unsigned short getWindowSize();
	unsigned short getCheckSum();

	void printTCP();
};

class HTTP {
private:
	int lenght;
	int end;
	char* message;
public:
	HTTP(IP* ipPacket);

	int getEnd();
	char* getMessage();

	void makeHTTPPacket(const unsigned char* pkt_data);
	void printHTTP();
	~HTTP();
};

typedef struct udp_hdr
{
	unsigned short sourcePort;  // source port - 16 bit
	unsigned short destPort;    // destination port - 16bit
	unsigned short length;   // Udp packet length - 16bit
	unsigned short checkSum; // Udp checksum (optional) - 16bit
} UDP_HDR;

class UDP {
private:
	UDP_HDR* udpHeader;
public:
	UDP(UDP_HDR* udpHeader);
	void makeUDPPacket(const unsigned char* pkt_data);

	void setSourcePort(unsigned short sourcePort);
	void setDestPort(unsigned short destPort);
	void setLength(unsigned short length);
	void setCheckSum(unsigned short checkSum);


	unsigned short getSourcePort();
	unsigned short getDestPort();
	unsigned short getLength();
	unsigned short getCheckSum();

	void printUDP();
};
typedef struct icmp_hdr
{
	unsigned char type;			// icmp type - 8 bit
	unsigned char code;			// icmp code - 8 bit
 	unsigned short checkSum;	// checksum - 16 bit
}ICMP_HDR;
class ICMP {
private:
	ICMP_HDR* icmpHeader;
public:
	ICMP(ICMP_HDR* icmpHeader);
	void makeICMPPacket(const unsigned char* pkt_data);

	void setType(unsigned char type);
	void setCode(unsigned char code);
	void setCheckSum(unsigned short checkSum);

	unsigned char getType();
	unsigned char getCode();
	unsigned short getCheckSum();

	void printICMP();
};

typedef struct dns_hdr
{
	unsigned short id;			 // identification number

	unsigned char qr : 1;		 // query/response flag
	unsigned char opcode : 4;	 // purpose of message
	unsigned char aa : 1;	 	 // authoritive answer
	unsigned char tc : 1;	     // truncated message
	unsigned char rd : 1;		 // recursion desired
	unsigned char ra : 1;		 // recursion available
	unsigned char z : 1;		 // its z! reserved
	unsigned char ad : 1;		 // authenticated data
	unsigned char cd : 1;		 // checking disabled
	unsigned char rcode : 4;	 // response code
	
	unsigned short totalQuestions; // number of question entries - 16 bit

	unsigned short totalAnswers; // number of answer entries - 16 bit

	unsigned short totalAuthResource; // number of authority entries - 16 bit

	unsigned short totalAddResource; // number of resource entries - 16 bit
} DNS_HDR;

