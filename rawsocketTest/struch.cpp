#include "struct.h"
#include "define.h"

/*
*--------------------------------------------------------------------------------------------
*-------------------------------------------IP 구현부---------------------------------------
*--------------------------------------------------------------------------------------------
*/


IP::IP(IPV4_HDR* ipHeader) {
	this->ipHeader = ipHeader;
}
void IP::makeIPPacket(const unsigned char* pkt_data) {
	
	this->setVersion(pkt_data[14] / 16);
	this->setHeaderLength(pkt_data[14] % 16);
	this->setTypeOfService(pkt_data[15]);
	this->setTotalLength(pkt_data[16] * 256 + pkt_data[17]);
	this->setIdentification(pkt_data[18] * 256 + pkt_data[19]);
	this->setTTL(pkt_data[22]);
	this->setProtocolType(pkt_data[23]);
	this->setCheckSum(pkt_data[24] * 256 + pkt_data[25]);
	this->setSourceAddress(pkt_data[26], 1);
	this->setSourceAddress(pkt_data[27], 2);
	this->setSourceAddress(pkt_data[28], 3);
	this->setSourceAddress(pkt_data[29], 4);
	this->setDestinationAddress(pkt_data[30], 1);
	this->setDestinationAddress(pkt_data[31], 2);
	this->setDestinationAddress(pkt_data[32], 3);
	this->setDestinationAddress(pkt_data[33], 4);
}
void IP::setVersion(char version) {
	this->ipHeader->version = version;
}

unsigned char IP::getVersion() {
	return this->ipHeader->version;
}

void IP::setHeaderLength(char headerLength) {
	this->ipHeader->headerLength = headerLength;
}

unsigned char IP::getHeaderLength() {
	return this->ipHeader->headerLength;
}

void IP::setTypeOfService(char typeOfService) {
	this->ipHeader->typeOfService = typeOfService;
}

unsigned char IP::getTypeOfService() {
	return this->ipHeader->typeOfService;
}

void IP::setTotalLength(short totalLength) {
	this->ipHeader->totalLength = totalLength;
}

unsigned short IP::getTotalLength() {
	return this->ipHeader->totalLength;
}

void IP::setIdentification(short identification) {
	this->ipHeader->identification = identification;
}

unsigned short IP::getIdentification() {
	return this->ipHeader->identification;
}

void IP::setFragOffset(char fragOffset) {
	this->ipHeader->fragOffset = fragOffset;
}

unsigned char IP::getFragOffset() {
	return this->ipHeader->fragOffset;
}

void IP::setMoreFragment(char moreFragment) {
	this->ipHeader->moreFragment = moreFragment;
}

unsigned char IP::getMoreFragment() {
	return this->ipHeader->moreFragment;
}

void IP::setDontFragment(char dontFragment) {
	this->ipHeader->dontFragment = dontFragment;
}

unsigned char IP::getDontFragment() {
	return this->ipHeader->dontFragment;
}

void IP::setReservedZero(char reservedZero) {
	this->ipHeader->reservedZero = reservedZero;
}

unsigned char IP::getReservedZero() {
	return this->ipHeader->reservedZero;
}

void IP::setFragOffset1(char fragOffset1) {
	this->ipHeader->fragOffset1 = fragOffset1;
}

unsigned char IP::getFragOffset1() {
	return this->ipHeader->fragOffset1;
}

void IP::setTTL(char TTL) {
	this->ipHeader->TTL = TTL;
}

unsigned char IP::getTTL() {
	return this->ipHeader->TTL;
}

void IP::setProtocolType(char protocolType) {
	this->ipHeader->protocolType = protocolType;
}

unsigned char IP::getProtocolType() {
	return this->ipHeader->protocolType;
}

void IP::setCheckSum(short checkSum) {
	this->ipHeader->checkSum = checkSum;
}

unsigned short IP::getCheckSum() {
	return this->ipHeader->checkSum;
}

void IP::setSourceAddress(char sourceAddress,int index) {
	this->ipHeader->sourceAddress[index] = sourceAddress;
}

unsigned char IP::getSourceAddress(int index) {
	return this->ipHeader->sourceAddress[index];
}

void IP::setDestinationAddress(char destinationAddress, int index) {
	this->ipHeader->destinationAddress[index] = destinationAddress;
}

unsigned char IP::getDestinationAddress(int index) {
	return this->ipHeader->destinationAddress[index];
}

void IP::printIP() {
	printf("===================================================================\n");
	printf("| IP Packet\t\t\t\t\t\t\t|\n");
	printf("===================================================================\n");
	printf("\n");
	printf("-------------------------------------------------------------------\n");
	printf("| Version : %d | Header Length : %d Bytes\t| Type : %d  |\n", (unsigned int)this->getVersion(), (unsigned int)(this->getHeaderLength() * 4), (unsigned int)this->getTypeOfService());
	printf("-------------------------------------------------------------------\n");
	printf("| IP Total Length : %d Bytes \t\t\t\t|\n",this->getTotalLength());
	printf("-------------------------------------------------------------------\n");
	printf("| Identification : %d\t\t\t\t\t|\n", this->getIdentification());
	printf("-------------------------------------------------------------------\n");
	printf("| TTL : %d\t| Protocol : %d\t\t| Checksum : %d\t|\n", (unsigned int)this->getTTL(), (unsigned int)this->getProtocolType(), this->getCheckSum());
	printf("-------------------------------------------------------------------\n");
	printf("| Source IP : %d.%d.%d.%d\t\t\t\t\t|\n", this->getSourceAddress(1),
		this->getSourceAddress(2), this->getSourceAddress(3), this->getSourceAddress(4));
	printf("-------------------------------------------------------------------\n");
	printf("| Destination IP :%d.%d.%d.%d\t\t\t\t|\n", this->getDestinationAddress(1),
		this->getDestinationAddress(2), this->getDestinationAddress(3),this->getDestinationAddress(4));
	printf("-------------------------------------------------------------------\n");
	printf("\n\n");
}

void IP::fPrintIP(FILE* fp) {
	fprintf(fp, "===============================================\n");
	fprintf(fp, "| IP Packet\t\t\t\t\t\t|\n");
	fprintf(fp, "===============================================\n");
	fprintf(fp, "\n");
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Version : %d \t| Header Length : %d Bytes\t| Type : %d\t|\n", (unsigned int)this->getVersion(), (unsigned int)(this->getHeaderLength() * 4), (unsigned int)this->getTypeOfService());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| IP Total Length : %d Bytes \t\t\t\t|\n", this->getTotalLength());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Identification : %d\t\t\t\t|\n", this->getIdentification());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| TTL : %d\t| Protocol : %d\t| Checksum : %d|\n", (unsigned int)this->getTTL(), (unsigned int)this->getProtocolType(), this->getCheckSum());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Source IP : %d.%d.%d.%d\t\t\t\t|\n", this->getSourceAddress(1),
		this->getSourceAddress(2), this->getSourceAddress(3), this->getSourceAddress(4));
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Destination IP :%d.%d.%d.%d\t\t\t|\n", this->getDestinationAddress(1),
		this->getDestinationAddress(2), this->getDestinationAddress(3), this->getDestinationAddress(4));
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "\n\n");
}
/*
*--------------------------------------------------------------------------------------------
*-------------------------------------------TCP 구현부---------------------------------------
*--------------------------------------------------------------------------------------------
*/


TCP::TCP(TCP_HDR* tcpHeader) {
	this->tcpHeader = tcpHeader;
}

void TCP::makeTCPPacket(const unsigned char* pkt_data) {
	this->setSourcePort(pkt_data[34] * 256 + pkt_data[35]);
	this->setDestPort(pkt_data[36] * 256 + pkt_data[37]);
	this->setSequenceNumber(pkt_data[38] * 16777216 + pkt_data[39] * 65536 + pkt_data[40] * 256 + pkt_data[41]);
	this->setAcknowledgeNumber(pkt_data[42] * 16777216 + pkt_data[43] * 65536 + pkt_data[44] * 256 + pkt_data[45]);
	this->setDataOffset((pkt_data[46]/16) * 4);
	this->setWindowSize(pkt_data[48] * 256 + pkt_data[49]);
	this->setCheckSum(pkt_data[50] * 256 + pkt_data[51]);
}

void TCP::setSourcePort(short sourcePort) {
	this->tcpHeader->sourcePort = sourcePort;
}

unsigned short TCP::getSourcePort() {
	return this->tcpHeader->sourcePort;
}

void TCP::setDestPort(short destPort) {
	this->tcpHeader->destPort = destPort;
}

unsigned short TCP::getDestPort() {
	return this->tcpHeader->destPort;
}

void TCP::setSequenceNumber(unsigned int sequenceNumber) {
	this->tcpHeader->sequenceNumber = sequenceNumber;
}

unsigned int TCP::getSequenceNumber() {
	return this->tcpHeader->sequenceNumber;
}
void TCP::setAcknowledgeNumber(unsigned int acknowledgeNumber) {
	this->tcpHeader->acknowledgeNumber = acknowledgeNumber;
}

unsigned int TCP::getAcknowledgeNumber() {
	return this->tcpHeader->acknowledgeNumber;
}

void TCP::setDataOffset(char dataOffset) {
	this->tcpHeader->dataOffset = dataOffset;
}

unsigned char TCP::getDataOffset() {
	return this->tcpHeader->dataOffset;
}

void TCP::setWindowSize(short windowSize) {
	this->tcpHeader->windowSize = windowSize;
}

unsigned short TCP::getWindowSize() {
	return this->tcpHeader->windowSize;
}

void TCP::setCheckSum(short checkSum) {
	this->tcpHeader->checkSum = checkSum;
}

unsigned short TCP::getCheckSum() {
	return this->tcpHeader->checkSum;
}

void TCP::printTCP() {
	printf("===================================================================\n");
	printf("| TCP Packet\t\t\t\t\t\t\t|\n");
	printf("===================================================================\n");
	printf("\n");
	printf("-------------------------------------------------------------------\n");
	printf("| Source Port : %d \t\t| Destination Port : %d\t\t|\n", this->getSourcePort(), this->getDestPort());
	printf("-------------------------------------------------------------------\n");
	printf("| Sequence Number : %u  \t\t\t\t|\n", this->getSequenceNumber());
	printf("-------------------------------------------------------------------\n");
	printf("| Acknowledge Number : %u\t\t\t\t|\n", this->getAcknowledgeNumber());
	printf("-------------------------------------------------------------------\n");
	printf("| Header Length : %d Bytes\t\t\t\t\t|\n", this->getDataOffset());
	printf("-------------------------------------------------------------------\n");
	printf("| Window : %d\t\t\t\t\t\t\t|\n", this->getWindowSize());
	printf("-------------------------------------------------------------------\n");
	printf("| Checksum : %d  \t\t\t\t\t\t|\n",this->getCheckSum());
	printf( "-------------------------------------------------------------------\n");
	printf("\n\n");
}

void TCP::fPrintTCP(FILE* fp) {
	fprintf(fp, "===============================================\n");
	fprintf(fp, "| TCP Packet\t\t\t\t\t\t|\n");
	fprintf(fp, "===============================================\n");
	fprintf(fp, "\n");
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Source Port : %d \t\t| Destination Port : %d\t|\n", this->getSourcePort(), this->getDestPort());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Sequence Number : %u  \t\t\t|\n", this->getSequenceNumber());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Acknowledge Number : %u\t\t\t|\n", this->getAcknowledgeNumber());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Header Length : %d Bytes\t\t\t\t|\n", this->getDataOffset());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Window : %d\t\t\t\t\t|\n", this->getWindowSize());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Checksum : %d  \t\t\t\t|\n", this->getCheckSum());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "\n\n");
}
/*
*--------------------------------------------------------------------------------------------
*-------------------------------------------UDP 구현부---------------------------------------
*--------------------------------------------------------------------------------------------
*/


UDP::UDP(UDP_HDR* udpHeader) {
	this->udpHeader = udpHeader;
}

void UDP::makeUDPPacket(const unsigned char* pkt_data) {
	this->setSourcePort(pkt_data[34] * 256 + pkt_data[35]);
	this->setDestPort(pkt_data[36] * 256 + pkt_data[37]);
	this->setLength(pkt_data[38] * 256 + pkt_data[39]);
	this->setCheckSum(pkt_data[40] * 256 + pkt_data[41]);
}

void UDP::setSourcePort(unsigned short sourcePort) {
	this->udpHeader->sourcePort = sourcePort;
}

unsigned short UDP::getSourcePort() {
	return this->udpHeader->sourcePort;
}
void UDP::setDestPort(unsigned short destPort) {
	this->udpHeader->destPort = destPort;
}

unsigned short UDP::getDestPort() {
	return this->udpHeader->destPort;
}
void UDP::setLength(unsigned short length) {
	this->udpHeader->length = length;
}

unsigned short UDP::getLength() {
	return this->udpHeader->length;
}

void UDP::setCheckSum(unsigned short checkSum) {
	this->udpHeader->checkSum = checkSum;
}

unsigned short UDP::getCheckSum() {
	return this->udpHeader->checkSum;
}

void UDP::printUDP() {
	printf("===================================================================\n");
	printf("| UDP Packet\t\t\t\t\t\t\t|\n");
	printf("===================================================================\n");
	printf("\n");
	printf("-------------------------------------------------------------------\n");
	printf("| Source Port : %d \t\t| Destination Port : %d\t\t|\n", this->getSourcePort(), this->getDestPort());
	printf("-------------------------------------------------------------------\n");
	printf("| Length : %d\t\t\t| Checksum : %d\t\t|\n", this->getLength(), this->getCheckSum());
	printf("-------------------------------------------------------------------\n");
	printf("\n\n");
};

void UDP::fPrintUDP(FILE* fp) {
	fprintf(fp, "===============================================\n");
	fprintf(fp, "| UDP Packet\t\t\t\t\t\t|\n");
	fprintf(fp, "===============================================\n");
	fprintf(fp, "\n");
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Source Port : %d \t| Destination Port : %d\t|\n", this->getSourcePort(), this->getDestPort());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Length : %d\t\t| Checksum : %d  |\n", this->getLength(), this->getCheckSum());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "\n\n");
};
/*
*--------------------------------------------------------------------------------------------
*-------------------------------------------ICMP 구현부---------------------------------------
*--------------------------------------------------------------------------------------------
*/

ICMP::ICMP(ICMP_HDR* icmpHeader, IP* IPClass) {
	this->icmpHeader = icmpHeader;
	this->length = IPClass->getTotalLength() + MacAddressLength;
}
void ICMP::makeICMPPacket(const unsigned char* pkt_data) {
	this->setType(pkt_data[34]);
	this->setCode(pkt_data[35]);
	this->setCheckSum(pkt_data[36] * 256 + pkt_data[37]);

	message = (char*)malloc(sizeof(char) * 1500);
	int j = 0;
	for (int i = ICMP_DATA_START_POINT; i < this->length; i++, j++) {
		message[j] = pkt_data[i];
	}
	this->end = j;
}

void ICMP::setType(unsigned char type) {
	this->icmpHeader->type = type;
}

unsigned char ICMP::getType() {
	return this->icmpHeader->type;
}
void ICMP::setCode(unsigned char code) {
	this->icmpHeader->code = code;
}

unsigned char ICMP::getCode() {
	return this->icmpHeader->checkSum;
}

void ICMP::setCheckSum(unsigned short checkSum) {
	this->icmpHeader->checkSum = checkSum;
}
unsigned short ICMP::getCheckSum() {
	return this->icmpHeader->checkSum;
}

int ICMP::getEnd() {
	return this->end;
}

char* ICMP::getMessage() {
	return this->message;
}

void ICMP::printICMP() {
	printf("===================================================================\n");
	printf("| ICMP Packet\t\t\t\t\t\t|\n");
	printf("===================================================================\n");
	printf("\n");
	printf("-------------------------------------------------------------------\n");
	printf("| Type : %d\t\t\t| Code : %d\t\t|\n", this->getType(), this->getCode());
	printf("-------------------------------------------------------------------\n");
	printf("| Checksum : %d  \t\t\t\t\t\t|\n", this->getCheckSum());
	printf("-------------------------------------------------------------------\n");
	printf("| ICMP Data\t\t\t\t\t\t\t|\n");
	printf("-------------------------------------------------------------------\n");
	char* message = this->getMessage();
	for (int i = 0; i < this->getEnd(); i++) {
		printf("%c", message[i]);
	}
	printf("\n");
	printf("-------------------------------------------------------------------\n");
	printf("\n\n");
}

void ICMP::fPrintICMP(FILE* fp) {
	fprintf(fp, "===============================================\n");
	fprintf(fp, "| ICMP Packet\t\t\t\t\t\t|\n");
	fprintf(fp, "===============================================\n");
	fprintf(fp, "\n");
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Type : %d\t\t| Code : %d\t\t|\n", this->getType(), this->getCode());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Checksum : %d  \t\t\t\t|\n", this->getCheckSum());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| ICMP Data\t\t\t\t\t|\n");
	fprintf(fp, "-------------------------------------------------------------------\n");
	char* message = this->getMessage();
	for (int i = 0; i < this->getEnd(); i++) {
		fprintf(fp, "%c", message[i]);
	}
	fprintf(fp, "\n");
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "\n\n");
}

/*
*--------------------------------------------------------------------------------------------
*-------------------------------------------HTTP 구현부---------------------------------------
*--------------------------------------------------------------------------------------------
*/


HTTP::HTTP(IP* ipPacket) {
	this->lenght = ipPacket->getTotalLength();		//-1은 인덱스가 0부터 시작하기때문이다.
}

int HTTP::getEnd() {
	return this->end;
}

char* HTTP::getMessage() {
	return this->message;
}

void HTTP::makeHTTPPacket(const unsigned char* pkt_data) {
	message = (char*)malloc(sizeof(char) * 1500);
	int j = 0;
	for (int i = IP_TCPPacketHeaderLength; i < this->lenght; i++,j++) {
		message[j] = pkt_data[i];
	}
	this->end = j;
}

void HTTP::printHTTP() {
	printf("===================================================================\n");
	printf("| HTTP Packet\t\t\t\t\t\t\t|\n");
	printf("===================================================================\n");
	printf("\n");
	printf("-------------------------------------------------------------------\n");
	char* message = this->getMessage();
	for (int i = 0; i < this->getEnd(); i++) {
		printf("%c", message[i]);
		if (message[i] == 13) {
			printf("\n");
			i++;
		}
	}
	printf("\n\n");
	printf("-------------------------------------------------------------------\n");
	printf("\n\n");
}

void HTTP::fPrintHTTP(FILE* fp) {
	fprintf(fp, "===============================================\n");
	fprintf(fp, "| HTTP Packet\t\t\t\t\t\t|\n");
	fprintf(fp, "===============================================\n");
	fprintf(fp, "\n");
	fprintf(fp, "-------------------------------------------------------------------\n");
	char* message = this->getMessage();
	for (int i = 0; i < this->getEnd(); i++) {
		fprintf(fp, "%c", message[i]);
		if (message[i] == 13) {
			fprintf(fp, "\n");
			i++;
		}
	}
	fprintf(fp, "\n\n");
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "\n\n");
}

HTTP::~HTTP() {
	free(this->message);
}

/*
*--------------------------------------------------------------------------------------------
*-------------------------------------------DNS 구현부---------------------------------------
*--------------------------------------------------------------------------------------------
*/

DNS::DNS(DNS_HDR* dnsHeader, IP* IPClass) {
	this->dnsHeader = dnsHeader;
	this->length = IPClass->getTotalLength() + MacAddressLength;
}

void DNS::makeDNSPacket(const unsigned char* pkt_data) {

	this->setID(pkt_data[42] * 256 + pkt_data[43]);
	this->setTotalQuestions(pkt_data[46] * 256 + pkt_data[47]);
	this->setTotalAnswers(pkt_data[48] * 256 + pkt_data[49]);
	this->setTotalAuthResource(pkt_data[50] * 256 + pkt_data[51]);
	this->setTotalAddResource(pkt_data[52] * 256 + pkt_data[53]);

	message = (char*)malloc(sizeof(char) * 458);	//dns의 최대크기는 512비트이며 헤더크기는 54비트이다
	int j = 0;
	for (int i = DNSPacketHeaderLength; i < this->length; i++, j++) {
		message[j] = pkt_data[i];
	}
	this->end = j;
}

void DNS::setID(unsigned short ID) {
	this->dnsHeader->id = ID;
}

unsigned short DNS::getID() {
	return this->dnsHeader->id;
}

void DNS::setTotalQuestions(unsigned short totalQuestions) {
	this->dnsHeader->totalQuestions = totalQuestions;
}

unsigned short DNS::getTotalQuestions() {
	return this->dnsHeader->totalQuestions;
}

void DNS::setTotalAnswers(unsigned short totalAnswers) {
	this->dnsHeader->totalAnswers = totalAnswers;
}

unsigned short DNS::getTotalAnswers() {
	return this->dnsHeader->totalAnswers;
}
void DNS::setTotalAuthResource(unsigned short totalAuthResource) {
	this->dnsHeader->totalAuthResource = totalAuthResource;
}

unsigned short DNS::getTotalAuthResource() {
	return this->dnsHeader->totalAuthResource;
}

void DNS::setTotalAddResource(unsigned short totalAddResource) {
	this->dnsHeader->totalAddResource = totalAddResource;
}

unsigned short DNS::getTotalAddResource() {
	return this->dnsHeader->totalAddResource;
}

int DNS::getEnd() {
	return this->end;
}


char* DNS::getMessage() {
	return this->message;
}

void DNS::printDNS() {
	printf("===================================================================\n");
	printf("| DNS Packet\t\t\t\t\t\t\t|\n");
	printf("===================================================================\n");
	printf("\n");
	printf("-------------------------------------------------------------------\n");
	printf("| Transaction ID : %d\t\t\t\t\t\t|\n", this->getID());
	printf("-------------------------------------------------------------------\n");
	printf("| Questions : %d\t\t\t| Answer RR : %d\t\t\t|\n", this->getTotalQuestions(), this->getTotalAnswers());
	printf("-------------------------------------------------------------------\n");
	printf("| Authority RR : %d\t\t| Additional RR : %d\t\t|\n", this->getTotalAuthResource(), this->getTotalAddResource());
	printf("-------------------------------------------------------------------\n");
	printf("| DNS Answers\t\t\t\t\t\t\t|\n");
	printf("-------------------------------------------------------------------\n");
	char* message = this->getMessage();
	for (int i = 0; i < this->getEnd(); i++) {
		printf("%c", message[i]);
	}
	printf("\n");
	printf("-------------------------------------------------------------------\n");
	printf("\n\n");
}

void DNS::fPrintDNS(FILE* fp) {
	fprintf(fp, "===============================================\n");
	fprintf(fp, "| DNS Packet\t\t\t\t\t\t|\n");
	fprintf(fp, "===============================================\n");
	fprintf(fp, "\n");
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Transaction ID : %d\t\t\t\t\t|\n", this->getID());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Questions : %d  \t\t| Answer RR : %d\t\t|\n", this->getTotalQuestions(), this->getTotalAnswers());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| Authority RR : %d\t\t| Additional RR : %d\t\t|\n", this->getTotalAuthResource(), this->getTotalAddResource());
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "| DNS Answers\t\t\t\t\t|\n");
	fprintf(fp, "-------------------------------------------------------------------\n");
	char* message = this->getMessage();
	for (int i = 0; i < this->getEnd(); i++) {
		fprintf(fp, "%c", message[i]);
	}
	fprintf(fp, "\n");
	fprintf(fp, "-------------------------------------------------------------------\n");
	fprintf(fp, "\n\n");
}