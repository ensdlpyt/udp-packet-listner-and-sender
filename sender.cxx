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

//read a media file, encrypt it and send it to receiver

char const *filename = "file.ts";
size_t const MAX_BYTE = (188<<1);
inline int read_and_send(){
	//file point
	FILE *fp = fopen(filename, "rb");
	if( fp == NULL){
		puts("failed to open media file ");
		return 0;
	}
	//168 byte kore porbo until end of line
	unsigned char byte_buffer[MAX_BYTE]={0};
	memset(byte_buffer,0x0, sizeof(byte_buffer) );

	size_t file_size,itr;
	int byte_read;
	//obtain the file size
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	printf("%lu byte\n",file_size);

	//network accessories
	int	sd;
	struct	sockaddr_in server;
									//IPPROTO_UDP
	sd = socket (AF_INET,SOCK_DGRAM,0); 
	if( sd<0 ){
		puts("cann't open socket!");
		return 1;
	}
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("192.168.42.20");
	server.sin_port = htons(1935);

	AES_KEY enc_key;

	size_t encslength = calculate_enclen(MAX_BYTE);

	unsigned char enc_out[encslength];
	AES_set_encrypt_key(aes_key, 128, &enc_key);

	//start reading file
	fseek(fp,0,SEEK_SET);
	for(itr=0; itr<file_size;itr+= MAX_BYTE){
		byte_read = fread(byte_buffer,1,MAX_BYTE,fp);
		if( byte_read < 0 ){
			printf("ERROR\n");
			break;
		}
		if( byte_read==0 ){
			printf("DONE READING ");
			break;
		}
		if( byte_read < MAX_BYTE ){
			memset(&byte_buffer[byte_read],0, MAX_BYTE-byte_read);
		}
	
		memset(enc_out, 0x0, sizeof(enc_out) );
		AES_cbc_encrypt(byte_buffer, enc_out, byte_read, &enc_key, iv_enc, AES_ENCRYPT);		
		int sendSize = sendto(sd, enc_out, calculate_enclen(MAX_BYTE) , 0, (struct sockaddr*) &server, sizeof(server));

		//hex_print(byte_buffer,sizeof(byte_buffer));
		cout<<"byte read from file "<<byte_read<<"\nbyte buffer size "<<MAX_BYTE<<"\nencode byte length "<<encslength<<"\nSending data "<<sendSize<<"\n";
		//break;		
		wait(.01);
	}
	byte_buffer[0]=0;
	fclose(fp);
	puts("done reading media file");
}

int main(){	
	/*unsigned char str[12] = "hello world";
	unsigned char *enc_out = get_encrypt_data(str, 12);
	unsigned char *dec_out = get_decrypt_data(enc_out, 12);
	cout<<dec_out<<"\n";*/

	read_and_send();
	return 0;
}