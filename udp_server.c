#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h> /* close() */
#include <string.h> /* memset() */



#define LOCAL_SERVER_PORT 10000
#define MAX_MSG 100 

int main(){

  int   sd;
  struct sockaddr_in server;
  char buf[MAX_MSG];


  puts("try creating socket");

  sd = socket (AF_INET,SOCK_DGRAM,0);
  if( sd<0 ){
    puts("cann't open socket!");
    return 1;
  }


  puts("try binding local server port");
  server.sin_family = AF_INET;  
  server.sin_addr.s_addr = htonl(INADDR_ANY);
  server.sin_port = htons(10000);

  
  int rc;
  rc = bind( sd,  (struct sockaddr *) &server, sizeof(server));
  if(rc<0){
    puts("cann't bind port number ");
    return 1;
  }

  printf("waiting for connection %u\n",LOCAL_SERVER_PORT);

  for(;;){
    rc=recv (sd, buf, sizeof(buf), 0);
    buf[rc]= (char) NULL;
    printf("Received: %s\n", buf);
  }

   return 0;
}