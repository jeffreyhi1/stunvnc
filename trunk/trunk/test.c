#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
    
#define BUFLEN 512
#define NPACK 10
#define PORT 1500
    
#define log(fmt, ...) printf(fmt"\n", ##__VA_ARGS__)
    
int main()
{
	struct sockaddr_in si_me, si_stun;
	int s;
	char buf[BUFLEN];

	if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
	{
		log("Erro, socket");
		return -1;
	}

	memset(&si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_stun.sin_addr.s_addr= htonl(0);
	si_stun.sin_port    = htons(0);
	if (bind(s, (struct sockaddr*)&si_me, sizeof(struct sockaddr))==-1)
	{
		log("bind failed");
		return -1;
	}
	
	//75.101.138.128

	si_stun.sin_addr.s_addr = htonl(inet_network("127.0.0.1"));
	si_stun.sin_port    = htons(PORT);
	si_stun.sin_family = AF_INET;
	strcpy(buf, "a udp msg from local");
	int iRet = sendto(s, buf, 10, 0, (struct sockaddr*) &si_stun, sizeof(si_stun));
	log("Sendto Result :%d", iRet);

	struct sockaddr sockFrom;
	char buffIn[BUFLEN];

	
	close(s);
	return 0;
}

