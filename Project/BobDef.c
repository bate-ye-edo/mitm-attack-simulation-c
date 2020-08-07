#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>   // vedi "man 7" ip, non "man ip"!
#include <string.h>
#include"mkaddr.c"
#include<time.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <string.h>
#define MAXBUF 2048
#define SERVERPORT 3002
#define SERVERNAME "localhost"


 
int padding = RSA_PKCS1_PADDING;
 
RSA * createRSAWithFilename(char * filename,int public){
    FILE * fp = fopen(filename,"rb");
 
    if(fp == NULL){
        printf("Unable to open file %s \n",filename);
        return NULL;    
    }
    RSA *rsa= RSA_new() ;
 
    if(public){
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
    }
    else{
        rsa = PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);
    }
 
    return rsa;
}
 
int public_encrypt(unsigned char * data,int data_len,unsigned char * filename, unsigned char *encrypted){
    RSA * rsa = createRSAWithFilename(filename,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * filename, unsigned char *decrypted){
    RSA * rsa = createRSAWithFilename(filename,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
 
void printLastError(char *msg){
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}

//En socket pasaremos esta estructura, de tal manera que el contrario pueda tener el mensaje y el tamaño del encryptado
struct Encriptacion{
    unsigned char encrip[4096];
    int tamEn;
};
 
int main(){
	srand(getpid());
/*---------------ParteServidor-------------*/
    int server_socket, connect_socket;
	socklen_t client_addr_len;
	int retcode;
	struct sockaddr_in client_addr, server_addr; 
	char pub[100];
    char priv[100];
    int nonce;
    char cadenaNonce[2048/8];
    nonce = rand();
    sprintf(cadenaNonce,"%d",nonce);

    strcpy(priv,"bob.pem");

	if ( (server_socket = socket(AF_INET,SOCK_STREAM,0)) == -1){
		perror("opening server socket"); 
		exit(-1);
	} 
	mkaddr(&server_addr, SERVERNAME, htons(SERVERPORT));

	retcode = bind(server_socket,(struct sockaddr *) &server_addr, sizeof(server_addr) );
	if(retcode == -1){
		perror("error binding socket"); 
		exit(-1);
	}

	retcode = listen(server_socket, 1);
	if(retcode == -1){
		perror("error listening");
		exit(-1);
	}
	printf("-------------------------Bob ready-------------------\n");
	printf(">Waiting for some connection...\n");
	unsigned char decr[4096];
	int decr_length;
	client_addr_len = sizeof(client_addr);
	int x=0;
	char textoPlano[2048/8];
	char delimitador[10] = ",";

	while ( 1 ) {
		/*Autenticacion*/
		struct Encriptacion res;
		struct Encriptacion envio;
		if ((connect_socket = accept(server_socket,(struct sockaddr *) & client_addr, &client_addr_len)) == -1) {
			perror("accepting");
			close(server_socket);
			exit(-1);
		}
		printf(">Autentificating...\n");
		/*Recibir primer mensaje*/
		printf(">ecrypting message...\n");
		sleep(1);
		retcode = read( connect_socket, &res, sizeof(res) );
		decr_length = private_decrypt(res.encrip,res.tamEn,priv,decr);
		printf(">Decrypted message: %s\n",decr);
		printf(">Who has written the message?\n");
		printf(">Press 1 if Alice\n>Press 2 if you don't know\n");
		int choice;
		scanf("%i",&choice);
		if(choice == 1){
			strcpy(pub,"alicepub.pem");
		}
		else{
			printf(">Closing connected socket...\n");
			close(connect_socket);
		}
		
		char *mdecr = strtok(decr,delimitador);
		char *returnNonce = strtok(NULL,delimitador);
		printf(">Message: %s\nNonce: %s\n",mdecr,returnNonce);
		strcpy(textoPlano,cadenaNonce);
		strcat(textoPlano,",");
		strcat(textoPlano,returnNonce);
		printf(">Sending my nonce, and returning the other nonce...\n");
		sleep(1);

	/*return the nonce received and my own nonce*/
		envio.tamEn = public_encrypt(textoPlano,(int)strlen(textoPlano)+1,pub,envio.encrip);
		if(write(connect_socket, &envio, sizeof(envio)) == -1){
			printf("Write error\n");
			exit(-1);
		}
		printf(">Sended\n");
		
	/*receiving the last nonce that send me, if is the same as my nonce, authentication success*/
		res.tamEn = 0;
		strcpy(res.encrip,"");
		printf(">Receiving authentication message....\n");
		if(read(connect_socket,&res, sizeof(res)) == -1){
			printf("Read error authentication\n");
			exit(-1);
		}
		strcpy(decr,"");
		decr_length = private_decrypt(res.encrip,res.tamEn,priv,decr);
		printf("Decripted 2: %s\n",decr);
		
		char respuesta[2048/8];
		if(atoi(decr) == nonce){
			printf("Authentication success\n");
			strcpy(textoPlano,"");
			printf(">For finish it, do CTRL + C\n");
			while(strcmp(textoPlano,"ENDCONNECTION") != 0){
				printf(">What do you want to say to Alice?: ");
				scanf(" %[^\n]s",textoPlano);
				if(write(connect_socket, &textoPlano, sizeof(textoPlano)) == -1){
					printf("Write error\n");
					exit(-1);
				}
				printf(">Sended\n");
				printf(">Waiting the answer...\n");
				sleep(1);
				if(read(connect_socket,respuesta, sizeof(char)*2048) == -1){
					printf("Read error authentication\n");
					exit(-1);
				}
				printf(">Answer: %s\n",respuesta);
				strcpy(textoPlano,"");
				strcpy(respuesta,"");
			}
		}

	}
}