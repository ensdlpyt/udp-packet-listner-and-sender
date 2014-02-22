/*
	file that will 
	1. listen ffmpeg -re -i file.ts -acodec copy -vcodec copy -f mpegts udp://192.168.42.20:1935?pkt_size=188
	2. encode it
	3. send it to recever.cxx
*/
#include "sys/types.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "arpa/inet.h"
#include "netdb.h"
#include "stdlib.h"
#include "stdio.h"
#include "unistd.h" /* close() */
#include "string.h" /* memset() */


#include <iostream>

#include <openssl/aes.h>
#include <openssl/rand.h>

using namespace std;
//12 byte char array
unsigned char aes_key[] = { 0x16, 0x50, 0x5F, 0x32, 0x13, 0x58, 0x67, 0xA1, 0xB1, 0x00, 0x03, 0x59, 0xE6, 0xD2, 0x87, 0x66};
unsigned char iv_enc[AES_BLOCK_SIZE] = { 0x36, 0xC1, 0x28, 0x0A, 0xD9, 0xBB, 0xFC, 0x08};
unsigned char iv_dec[AES_BLOCK_SIZE] = { 0x36, 0xC1, 0x28, 0x0A, 0xD9, 0xBB, 0xFC, 0x08};

// a simple hex-print routine. could be modified to print 16 bytes-per-line
//http://stackoverflow.com/questions/18152913/aes-aes-cbc-128-aes-cbc-192-aes-cbc-256-encryption-decryption-with-openssl-c?rq=1
static void hex_print(const void* pv, size_t len){
    const unsigned char * p = (const unsigned char*)pv;
    if (NULL == pv)
        printf("NULL");
    else
    {
        size_t i = 0;
        for (; i<len;++i)
            printf("%02X ", *p++);
    }
    printf("\n");
}

inline int generate_key(int keylength=128){
	 /* generate a key with a given length */
    unsigned char aes_key[keylength/8];
    memset(aes_key, 0x0, sizeof(aes_key));
    if (!RAND_bytes(aes_key, keylength/8)){
        return 0;
    }
    hex_print(aes_key, sizeof( aes_key ) );
    //cout<<sizeof(aes_key)<<"\n";
    return 1;
}

inline size_t calculate_enclen(size_t inputslength){
	return ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
}
inline void wait(double seconds) {
        double endtime = clock() + (seconds * CLOCKS_PER_SEC);
        while (clock() < endtime) {
                ;
        }
}

//listen, encrypt it and send it to receiver
size_t const MAX_BYTE = (188);
inline int listen_and_send(){

	//network accessories
	int	sd,cl;
	struct	sockaddr_in server,client;
									//IPPROTO_UDP
	sd = socket (AF_INET,SOCK_DGRAM,0); 
	cl = socket (AF_INET,SOCK_DGRAM,0); 
	if( sd<0 ){
		puts("cann't open socket!");
		return 1;
	}
	if( cl<0 ){
		puts("cann't open socket!");
		return 1;
	}

	server.sin_family = AF_INET;
	client.sin_family = AF_INET;

	server.sin_addr.s_addr = htonl(INADDR_ANY);
	client.sin_addr.s_addr = inet_addr("192.168.42.20");

	//ae port'a server listen korbe
	server.sin_port = htons(9090);
	//ae port'a server server korbe
	client.sin_port = htons(1935);


	puts("creating a socket to which i will listen, receive and send");
	
	int rc = bind( sd,  (struct sockaddr *) &server, sizeof(server));
	if(rc<0){
		puts("cann't bind port number ");
		return 1;
	}

	AES_KEY enc_key;
	size_t encslength = calculate_enclen(MAX_BYTE);
	unsigned char enc_out[encslength];
	AES_set_encrypt_key(aes_key, 128, &enc_key);


	int const byte_received_len = MAX_BYTE;
	unsigned char buf[byte_received_len];
	
	int clen,ln;
	clen = sizeof(client);
	//start listening
	for(;;){
		/* init buffer */
		memset(buf,0x0,sizeof (buf));
		ln=recv (sd, buf, byte_received_len, 0 );
		if( ln>0 ){
			memset(enc_out, 0x0, sizeof(enc_out) );
			AES_cbc_encrypt(buf, enc_out, ln, &enc_key, iv_enc, AES_ENCRYPT);
			int sendSize = sendto(cl, enc_out, encslength , 0, (struct sockaddr*) &client, sizeof(client));
			if( sendSize>0 ){
				cout<<"Byte stream from ffmpeg "<<ln<<"\nSend stream to receiver "<<sendSize<<"\n";
			}

		}
	}
}

int main(){	
	/*unsigned char str[12] = "hello world";
	unsigned char *enc_out = get_encrypt_data(str, 12);
	unsigned char *dec_out = get_decrypt_data(enc_out, 12);
	cout<<dec_out<<"\n";*/

	listen_and_send();
	return 0;
}