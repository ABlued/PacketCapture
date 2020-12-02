#include "struct.h"
#include <stdio.h>
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
	printf("\n");
}