#include <iostream>
#include <WinSock2.h>
#include <string.h>
#include <vector>
#include <fstream>
#include <map>
#include <algorithm>
#include "dns.h"

#pragma comment(lib, "ws2_32.lib")
#pragma pack(show)

using namespace std;


void init(int port = 53,int sendPort=32000,string dnsServerAddr="223.5.5.5")
{
	iptable.clear();
	readFile();

	memset(&dnsServerAddress, 0, sizeof(sockaddr_in));
	dnsServerAddress.sin_family = AF_INET;
	dnsServerAddress.sin_addr.S_un.S_addr = inet_addr(dnsServerAddr.c_str());
	dnsServerAddress.sin_port = htons(53);

	//set winsock version
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		printf("socket init failed\n");
		exit(-1);
	}
	//create socket
	if ((recvSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {
		printf("recv socket create failed");
		exit(-1);
	}

	struct sockaddr_in socketAddress;
	memset(&socketAddress, 0, sizeof(sockaddr_in));
	socketAddress.sin_family = AF_INET;
	socketAddress.sin_addr.S_un.S_addr = INADDR_ANY;
	socketAddress.sin_port = htons(port);

	//bind socket with port
	if (bind(recvSock, (sockaddr*)&socketAddress, sizeof(socketAddress)) == SOCKET_ERROR) {
		printf("bind recv socket error in port %d/n", port);
		exit(-1);
	}

	//create send socket
	if ((sendSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {
		printf("send socket create failed");
		exit(-1);
	}

	//set dns server addr
	socketAddress.sin_port = htons(sendPort);

	//bind send socket with port
	if (bind(sendSock, (sockaddr*)&socketAddress, sizeof(socketAddress)) == SOCKET_ERROR) {
		printf("bind send socket error in port %d/n", port);
		exit(-1);
	}

	/*
	//set the socket transfer data with dns server timeout
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	setsockopt(sendSock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
	setsockopt(sendSock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));
	*/
}

void destroy()
{
	closesocket(recvSock);
	WSACleanup();
}

void readFile()
{
	ifstream pIn;
	pIn.open("dnsrelay.txt", ios::in);
	if (!pIn)
	{
		cout << "cannot open file\n" << endl;
		return;
	}
	char ip[100], domain[100];
	string domainStr;
	while (!pIn.eof())
	{
		pIn >> ip >> domain;
		domainStr = domain;
		transform(domainStr.begin(), domainStr.end(), domainStr.begin(), ::tolower);
		iptable.insert(make_pair(encodeDotStr(domainStr.c_str()), inet_addr(ip)));
	}
	pIn.close();
}


void getClientRequests()
{
	char buf[BUF_SIZE];
	int udpSize;
	sockaddr_in remoteAddr;
	int lenAddr = sizeof(remoteAddr);
	DNSHeader* pDnsHeader;
	char* pDnsData;

	while (true)
	{
		memset(buf, 0, sizeof(buf));

		//recv query udp
		udpSize = recvfrom(recvSock, buf, BUF_SIZE, 0, (SOCKADDR*)&remoteAddr, &lenAddr);
		cout << "data:" << endl;
		for (int i = 0; i < udpSize; i++)
			cout << hex << (int)buf[i] << " ";
		cout << endl;
		cout << "addr:" << inet_ntoa(remoteAddr.sin_addr) << endl;
		cout << dec << "port:" << ntohs(remoteAddr.sin_port) << endl;

		pDnsHeader = (DNSHeader *)buf;
		//place pointer to the begin of dns data block
		pDnsData = buf + sizeof(DNSHeader);
		USHORT id = ntohs(pDnsHeader->id);
		USHORT flags = ntohs(pDnsHeader->flags);

		char encodedStr[128];
		string queryDomain;
		USHORT queryType;

		//get the query domain name and query type
		int encodedStrLen = strlen(pDnsData);
		memcpy(encodedStr, pDnsData, encodedStrLen + 1);
		cout << encodedStr << endl;
		queryDomain = encodedStr;
		pDnsData += encodedStrLen + 1;
		memcpy(&queryType, pDnsData, 2);
		queryType = ntohs(queryType);

		//transform domain to lower
		string lowerDomain = queryDomain;
		transform(lowerDomain.begin(), lowerDomain.end(), lowerDomain.begin(), ::tolower);

		map<string, unsigned long>::iterator iter;
		if ((iter = iptable.find(lowerDomain)) != iptable.end())
		{
			//domain in table
			if (iter->second == 0x00000000)
			{
				//ip==0.0.0.0
				//send not find
				char* sendBuf = (char *)malloc(udpSize);
				memcpy(sendBuf, buf, udpSize);
				DNSHeader* sendHeader = (DNSHeader*)sendBuf;

				//modify the header to sign it "not found"
				sendHeader->flags = htons(0x8183);
				sendto(recvSock, sendBuf, udpSize, 0, (sockaddr*)&remoteAddr, lenAddr);
				free(sendBuf);
			}
			else
			{
				if (queryType==QUERY_TYPE_A) {
					//ip was found and query is type A
					//send ans to client

					char* sendBuf = (char *)malloc(udpSize + 16);
					memcpy(sendBuf, buf, udpSize);
					DNSHeader* sendHeader = (DNSHeader*)sendBuf;
					AnswerHeader *sendData = (AnswerHeader *)(sendBuf + udpSize);
					sendHeader->flags = htons(0x8180);
					sendHeader->answerrrs = htons(1);

					//create answer data
					sendData->name = htons(0xC00C);
					sendData->type = htons(QUERY_TYPE_A);
					sendData->Aclass = htons(1);
					sendData->ttl = htonl(0x0);
					sendData->RDlength = htons(4);
					sendData->RData = iter->second;

					//send response to client
					sendto(recvSock, sendBuf, udpSize + 16, 0, (sockaddr*)&remoteAddr, lenAddr);
					free(sendBuf);
				}
				else
				{
					//query is not A
					//ask other server
					sendQueryToServer(udpSize, buf, remoteAddr);
				}
			}
		}
		else
		{
			//domain not in table
			//ask other server
			sendQueryToServer(udpSize, buf, remoteAddr);
		}

	}
}

//send query to other dns server
bool sendQueryToServer(const int querySize, const char* queryBuf,const sockaddr_in clientAddr)
{
	struct sockaddr_in tmpAddr;
	DNSHeader* ansHeader;
	int tmpLen = sizeof(tmpAddr), ansSize;
	char* ansBuf = (char*)malloc(BUF_SIZE);

	reassignID++;
	DNSHeader* queryHeader = (DNSHeader*)queryBuf;

	//reassign ID
	SHORT oldID = ntohs(queryHeader->id);
	queryHeader->id = htons(reassignID);

	//ask other dns server for response
	if (sendto(sendSock, queryBuf, querySize, 0, (SOCKADDR*)&dnsServerAddress, sizeof(dnsServerAddress)) > 0)
	{

		//set recv timeout
		fd_set fds;
		timeval tv = { 2,0 };
		FD_ZERO(&fds);
		FD_SET(sendSock, &fds);
		int ret = select(sendSock, &fds, NULL, NULL, &tv);
		if (ret > 0)
		{
			//get the response from other server
			ansSize = recvfrom(sendSock, ansBuf, BUF_SIZE, 0, (SOCKADDR*)&tmpAddr, &tmpLen);
			//restore id
			ansHeader = (DNSHeader*)ansBuf;
			ansHeader->id = htons(oldID);

			//send response to client
			sendto(recvSock, ansBuf, ansSize, 0, (struct sockaddr *)&clientAddr, sizeof(clientAddr));
			return true;
		}
		else if (ret == 0)
		{
			printf("==Recvfrom Timeout\n");
			return false;
		}
		else
		{
			printf("==error selecting\n");
			return false;
		}
	}
	else
	{
		printf("==error occured when send data to dns server");
		return false;
	}
}

//convert dotStr like "www.baidu.com" to "\x3www\x5baidu\x3com\0
string encodeDotStr(const char* dotStr)
{
	int lenDotStr = strlen(dotStr);
	char* dotStrCopy = new char[lenDotStr + 1];
	char* encodedStr = new char[lenDotStr + 2];
	int encodedStrSize = lenDotStr + 2;
	strcpy_s(dotStrCopy, lenDotStr + 1, dotStr);
	char* pNextToken = nullptr;
	char* pLabel = strtok_s(dotStrCopy, ".", &pNextToken);
	int nLabelLen = 0;
	int nEncodedStrlen = 0;

	while (pLabel != NULL)
	{
		if ((nLabelLen = strlen(pLabel)) != 0)
		{
			sprintf_s(encodedStr + nEncodedStrlen, encodedStrSize - nEncodedStrlen, "%c%s", nLabelLen, pLabel);
			nEncodedStrlen += (nLabelLen + 1);
		}
		pLabel = strtok_s(NULL, ".", &pNextToken);
	}
	delete[] dotStrCopy;
	return (string)encodedStr;
}

/*
void getMessage()
{
	char buf[2048];
	int bytes;
	sockaddr_in remoteAddr;
	int lenAddr = sizeof(remoteAddr);
	while (true)
	{
		memset(buf, 0, sizeof(buf));
		bytes = recvfrom(recvSock, buf, 2048, 0, (SOCKADDR*)&remoteAddr, &lenAddr);
		cout << "data:" << endl;
		for (int i = 0; i < bytes; i++)
			cout << hex << (int)buf[i] << " ";
		cout << endl;
		cout << "addr:" << inet_ntoa(remoteAddr.sin_addr) << endl;
		cout << dec << "port:" << ntohs(remoteAddr.sin_port) << endl;
	}
}
*/

int main(int argc, char** argv)
{
	init();
	getClientRequests();
	destroy();
	return 0;
}
