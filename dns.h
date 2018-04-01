#pragma once
#include <iostream>
#include <WinSock2.h>
#include <string>
#include <string.h>
#include <vector>
#include <fstream>
#include <map>
#include <algorithm>

#pragma pack(2)

using namespace std;

#define QUERY_TYPE_A 1
#define QUERY_TYPE_PTR 12

#define BUF_SIZE 2048

struct DNSHeader
{
	USHORT id : 16;
	USHORT flags : 16;
	USHORT questions : 16;
	USHORT answerrrs : 16;
	USHORT authorityrrs : 16;
	USHORT additionalrrs : 16;
};
struct AnswerHeader
{
	USHORT name : 16;
	USHORT type : 16;
	USHORT Aclass : 16;
	unsigned long ttl : 32;
	USHORT RDlength : 16;
	unsigned long RData : 32;
};


SOCKET recvSock;
SOCKET sendSock;
SHORT reassignID = 0;
WSADATA wsa;
map<string, unsigned long> iptable;
struct sockaddr_in dnsServerAddress;


void readFile();
void init(int port, int sendPort, string dnsServerAddr);
void destroy();
void getClientRequests();
string encodeDotStr(const char* dotStr);
void getMessage();
bool sendQueryToServer(const int querySize, const char* queryBuf, const sockaddr_in clientAddr);