#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h> /* close() */
#include <string.h> /* memset() */

#include <openssl/aes.h>
#include <openssl/rand.h>


#define MAX_MSG 1024

int key_length[] = {128,192,256};
#define MAX_LEN 1024


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

static void char_print(const void* pv, size_t len){
    const unsigned char * p = (const unsigned char*)pv;
    if (NULL == pv)
        printf("NULL");
    else
    {
        size_t i = 0;
        for (; i<len;++i)
            printf("%02c ", *p++);
    }
    printf("\n");
}

int main(int argc, char **argv){
	int	sd;
	struct	sockaddr_in server, client;
									//IPPROTO_UDP
	sd = socket (AF_INET,SOCK_DGRAM,0); 
	server.sin_family = AF_INET;
	if( argc!=3 ){
		puts("try ./client 127.0.0.1 9090");
		return 1;
	}
	server.sin_addr.s_addr = inet_addr(argv[1]);
	server.sin_port = htons(atoi(argv[2]));


	char buf[MAX_MSG];
	char recvbuf[MAX_MSG];
	int i,j,sendSize,clen;




    size_t inputslength;
    printf("available key length => ");
    for(i=0;i<3;++i){
      printf("%d ",key_length[i]);
    }puts("");


    //1: generate key
    int choice,keylength;
    printf("Choice  as %d\n",(choice=0));
    //scanf("%d", &choice);
    keylength = key_length[choice];
    /* generate a key with a given length */
    unsigned char aes_key[keylength/8];
    memset(aes_key, 0x0, sizeof(aes_key));
    if (!RAND_bytes(aes_key, keylength/8)){
        exit(-1);
    }
    hex_print(aes_key,sizeof aes_key);


    //2: necessary module for encryption
    /* init vector */
    unsigned char iv_enc[AES_BLOCK_SIZE];
    unsigned char iv_dec[AES_BLOCK_SIZE];
    RAND_bytes(iv_enc, AES_BLOCK_SIZE);
    memcpy(iv_dec, iv_enc, AES_BLOCK_SIZE);
    // so i can do with this aes-cbc-128 aes-cbc-192 aes-cbc-256
    AES_KEY enc_key,dec_key;
    AES_set_encrypt_key(aes_key, keylength, &enc_key);
    AES_set_decrypt_key(aes_key, keylength, &dec_key);


    

    while(1){
		// buffers for encryption
        //:3 encode given string and send to
        puts("Write something....");
        unsigned char input_string[MAX_LEN];
        memset(input_string, 0x0, sizeof (input_string));
        scanf("\n");
        gets(input_string);
        inputslength = strlen(input_string);

        const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        unsigned char enc_out[encslength];
        unsigned char dec_out[encslength];
        memset(enc_out, 0x0, sizeof(enc_out));
        memset(dec_out, 0, sizeof(dec_out));
        memset(buf, 0x0, sizeof(buf));

        AES_cbc_encrypt(input_string, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);
		
		memcpy(buf, enc_out, sizeof(enc_out) );
		sendSize = sendto(sd, buf, strlen(buf) , 0, (struct sockaddr*) &server, sizeof(server));



		printf("original:\t");
        hex_print(input_string, inputslength );
        printf("encrypt:\t");
        hex_print(enc_out, sizeof(enc_out));

		/* init buffer */
    	memset(recvbuf,0x0,MAX_MSG);
		int rc = recvfrom(sd,recvbuf, MAX_MSG, 0, (struct sockaddr *) &client, &clen );
		printf("receive from server as encrypted \t:");
		
		AES_cbc_encrypt(recvbuf, dec_out, inputslength, &dec_key, iv_dec, AES_DECRYPT);
		
		puts(dec_out);
		sleep(2);
	}

	close(sd);
	return 0;
}