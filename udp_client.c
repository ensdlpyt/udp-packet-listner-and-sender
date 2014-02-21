#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h> /* close() */
#include <string.h> /* memset() */


#define PORT_NUMBER 10000
#define MAX_MSG 100

int main(){
	int	sd;
	struct	sockaddr_in server;
									//IPPROTO_UDP
	sd = socket (AF_INET,SOCK_DGRAM,0); 
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_port = htons(PORT_NUMBER);


	char buf[MAX_MSG];
	int i,j,sendSize;
	for (i=1;i<=5;++i) {
		for(j=0;j<i;++j){
			buf[j]='P';
		}
		buf[j]=0;
		sendSize = sendto(sd, buf, strlen(buf) , 0, (struct sockaddr*) &server, sizeof(server));
		printf("Sending %d\n",sendSize);
		sleep(2);
	}

	close(sd);
	return 0;
}