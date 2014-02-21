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
#define BYTE_SIZE 12
//12 byte char array
unsigned char byte_array [BYTE_SIZE];
unsigned char aes_key[] = { 0x16, 0x50, 0x5F, 0x32, 0x13, 0x58, 0x67, 0xA1, 0xB1, 0x00, 0x03, 0x59, 0xE6, 0xD2, 0x87, 0x66};
unsigned char iv_enc[] = { 0x36, 0xC1, 0x28, 0x0A, 0xD9, 0xBB, 0xFC, 0x08};
unsigned char iv_dec[] = { 0x36, 0xC1, 0x28, 0x0A, 0xD9, 0xBB, 0xFC, 0x08};

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

inline void get_encrypt_data(unsigned char *normal_data, size_t inputslength, unsigned int keylength=128){
	AES_KEY enc_key;

	const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	unsigned char *enc_out = (unsigned char *)malloc( sizeof(unsigned char) *encslength );


	AES_set_encrypt_key(aes_key, keylength, &enc_key);
	AES_cbc_encrypt(normal_data, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);

	
	hex_print( normal_data, sizeof(normal_data));
	hex_print( enc_out, sizeof(enc_out));

	cout<<sizeof(normal_data)<<"\n";
	cout<<sizeof(enc_out)<<"\n";

	
	free( enc_out);
}
inline void get_decrypt_data(unsigned char *encrypted_data, size_t inputslength, unsigned int keylength=128){
	AES_KEY dec_key;
	const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	unsigned char *dec_out = (unsigned char *)malloc( sizeof(unsigned char) *encslength );

	AES_set_decrypt_key(aes_key, keylength, &dec_key);
	AES_cbc_encrypt(encrypted_data, dec_out, encslength, &dec_key, iv_dec, AES_DECRYPT);

	cout<<sizeof(dec_out)<<"\n";
	hex_print(dec_out, sizeof(dec_out));
}
int main(){	
	//generate_key();
	/*hex_print(aes_key, sizeof(aes_key));
	cout<<sizeof(aes_key)<<"\n";*/
	unsigned char data[12]="Hello world";
	cout<<sizeof( data ) <<"\n";
	get_encrypt_data( data,  sizeof( data ) );


	return 0;
}