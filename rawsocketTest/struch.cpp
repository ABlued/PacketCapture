#include "struct.h"
#include <stdio.h>

/*
*--------------------------------------------------------------------------------------------
*-------------------------------------------IP 备泅何---------------------------------------
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
	printf("| Version : %d \t| Header Length : %d Bytes\t| Type : %d\t|\n", (unsigned int)this->getVersion(), (unsigned int)(this->getHeaderLength() * 4), (unsigned int)this->getTypeOfService());
	printf("-------------------------------------------------------------------\n");
	printf("| IP Total Length : %d Bytes \t\t\t\t\t|\n",this->getTotalLength());
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


/*
*--------------------------------------------------------------------------------------------
*-------------------------------------------TCP 备泅何---------------------------------------
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


/*
*--------------------------------------------------------------------------------------------
*-------------------------------------------UDP 备泅何---------------------------------------
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
	printf("-------------------------------------------------------------------\n");
	printf("| Source Port : %d \t\t| Destination Port : %d\t\t|\n", this->getSourcePort(), this->getDestPort());
	printf("-------------------------------------------------------------------\n");
	printf("| Length : %d\t\t\t| Checksum : %d\t\t|\n", this->getLength(), this->getCheckSum());
	printf("-------------------------------------------------------------------\n");
	printf("\n\n");
};
