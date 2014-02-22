#include "sys/types.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "arpa/inet.h"
#include "netdb.h"
#include "stdlib.h"
#include "stdio.h"
#include "unistd.h" /* close() */
#include "string.h" /* memset() */
#include "assert.h"

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
inline unsigned char *get_encrypt_data(unsigned char *normal_data, size_t inputslength, unsigned int keylength=128){
	AES_KEY enc_key;
	size_t encslength = calculate_enclen(inputslength);

	unsigned char *enc_out=(unsigned char*)malloc(sizeof(unsigned char) *encslength);
	memset(enc_out, 0x0, sizeof(enc_out) );

	AES_set_encrypt_key(aes_key, keylength, &enc_key);
    AES_cbc_encrypt(normal_data, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);
	
	//hex_print(enc_out, encslength);
	return enc_out;
}

inline unsigned char *get_decrypt_data(unsigned char *encrypted_data, size_t inputslength, unsigned int keylength=128){
	AES_KEY dec_key;
	size_t encslength = calculate_enclen(inputslength);

    unsigned char *dec_out = (unsigned char*)malloc(sizeof(unsigned char) *inputslength);
    memset(dec_out, 0x0, sizeof(dec_out));

	AES_set_decrypt_key(aes_key, keylength, &dec_key);
    AES_cbc_encrypt(encrypted_data, dec_out, encslength, &dec_key, iv_dec, AES_DECRYPT);

	//hex_print(dec_out, inputslength);
	return dec_out;
}

inline void wait(double seconds) {
        double endtime = clock() + (seconds * CLOCKS_PER_SEC);
        while (clock() < endtime) {
                ;
        }
}

//read encrypted file sent from sender and send it to ffplay
size_t const MAX_BYTE = (188<<1);
inline int read_and_transmit(){
  int   sd,cl;
  struct sockaddr_in server, client;

  sd = socket (AF_INET,SOCK_DGRAM,0);
  cl = socket (AF_INET,SOCK_DGRAM,0);
  if( sd<0 ){
    puts("cann't open socket!");
    return 1;
  }
  if( cl<0 ){
    puts("cann't open client socket!");
    return 1;
  }
  server.sin_family = AF_INET; 
  client.sin_family = AF_INET;  

  server.sin_addr.s_addr = htonl(INADDR_ANY);
  server.sin_addr.s_addr = inet_addr("192.168.42.20");

  server.sin_port = htons( 1935 );
  client.sin_port = htons( 10000 );


  puts("creating a socket to which i will listen, receive and send");
  int rc;
  rc = bind( sd,  (struct sockaddr *) &server, sizeof(server));
  if(rc<0){
    puts("cann't bind port number ");
    return 1;
  }


	int ln,clen,hp;
	int const byte_received_len = calculate_enclen(MAX_BYTE);
	unsigned char buf[byte_received_len];


	AES_KEY dec_key;
	size_t encslength = calculate_enclen(MAX_BYTE);
	unsigned char dec_out[MAX_BYTE];
	AES_set_decrypt_key(aes_key, 128, &dec_key);

	for(;;){
		/* init buffer */
		memset(buf,0x0,calculate_enclen(MAX_BYTE));
		clen = sizeof(client);
		ln=recv (sd, buf, encslength, 0 );
		cout<<"Expected received size "<<byte_received_len<<"\nbyte received "<<ln<<"\n";
		assert( byte_received_len==ln );
		if(ln>0){
		    memset(dec_out, 0x0, sizeof(dec_out));
		    AES_cbc_encrypt(buf, dec_out, MAX_BYTE, &dec_key, iv_dec, AES_DECRYPT);

		    int sendSize = sendto(cl, dec_out, MAX_BYTE , 0, (struct sockaddr*) &client, sizeof(client));
		    /*hex_print(dec_out,sizeof(dec_out));
		    hex_print(dec_out,sendSize);
		    hex_print(dec_out,MAX_BYTE);
		    */
		    if(sendSize>0){
		    	cout<<"sending bytes "<<sendSize<<"\n";	
		    }
		    
		}else{
		    puts("could not receive data");
		}
	}
	
}

int main(){	
	read_and_transmit();
	return 0;
}