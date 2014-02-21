#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h> /* close() */
#include <string.h> /* memset() */



#define MAX_MSG 100 

int main(int argc, char **argv){

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

  if( argc!=2 ){
    puts("please prive port number to run [ ./server 9090]");
    return 1;
  }
  server.sin_port = htons( atoi(argv[1]) );

  puts("creating a socket to which i will listen, receive and send");
  int rc;
  rc = bind( sd,  (struct sockaddr *) &server, sizeof(server));

  if(rc<0){
    puts("cann't bind port number ");
    return 1;
  }

  printf("waiting for connection at port %d\n", atoi(argv[1]));
  memset(buf,0,sizeof buf);
  for(;;){
    rc=recv (sd, buf, sizeof(buf), 0);
    if(rc>0){
        printf("Received: %s\n", buf);
        buf[0]=0;
    }
  }

   return 0;
}