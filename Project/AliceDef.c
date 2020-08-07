#include <stdio.h>
#include <unistd.h> 
#include <stdlib.h> 
#include <string.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include<string.h>
#include <sys/socket.h>
#include <netdb.h> 
#include <netinet/in.h> 
#include <arpa/inet.h>
#include"mkaddr.c"
#include<time.h>
#define MAXBUF 2048
#define BOBPORT 3002
#define IVEPORT 4000
#define SERVERNAME "localhost"
#define IVESERVERNAME "ivehost"

int padding = RSA_PKCS1_PADDING;
 
RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
 
    return rsa;
}
RSA * createRSAWithFilename(char * filename,int public)
{
    FILE * fp = fopen(filename,"rb");
 
    if(fp == NULL)
    {
        printf("Unable to open file %s \n",filename);
        return NULL;    
    }
    RSA *rsa= RSA_new() ;
 
    if(public)
    {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);
    }
 
    return rsa;
}
 
int public_encrypt(unsigned char * data,int data_len, char * file, unsigned char *encrypted)
{
    RSA * rsa = createRSAWithFilename(file,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSAWithFilename("alice.pem",0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

 
void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}
struct Encriptacion{
    unsigned char encrip[4096];
    int tamEn;
};
 
int main(){
/*------------------------Parte CLiente------------*/
    srand(getpid());
    char textoPlano[2048/8];
    int client_socket, retcode, s_addr_len; 
    struct sockaddr_in server_addr;
    char pub[100];
    char priv[100];
    int nonce;
    int choice = 0;
    char cadenaNonce[2048/8];
    strcpy(priv,"alice.pem");
/*------------------------start menu------------------*/
    printf("----------------------------------Starting ALICE----------------------------------\n");
    
    while(choice != 1 && choice != 2){
        printf(">Please press 1 if you want to connect with BOB\n" );
        printf(">And press 2 if you want to connect with IVE\n");
        scanf("%i",&choice);
    }

    int PORT;
    char NAME[100];
    if(choice == 1){
        printf(">You have chosen: BOB\n");
        strcpy(pub,"bobp.pem");
        PORT=BOBPORT;
        strcpy(NAME,SERVERNAME);
    }
    else if(choice == 2){
        printf(">You have chosen: IVE\n");
        strcpy(pub,"ivep.pem");
        PORT = IVEPORT;
        strcpy(NAME,IVESERVERNAME);
    }



    client_socket = socket(AF_INET, SOCK_STREAM, 0); 
    if (client_socket == -1){
        perror(">opening client socket"); 
        exit(-1);
    }

    mkaddr(&server_addr, NAME, htons(PORT));
    
    retcode = connect(client_socket,         // not in sndrcvClessClnt.c
            (struct sockaddr *) &server_addr, 
            s_addr_len = sizeof(server_addr) ); 
    if (retcode == -1) {
        perror("connecting socket"); 
        exit(-1);
    }
/*Autenticacion*/
    printf(">Autenticating...\n");
    nonce = rand();
    sprintf(cadenaNonce,"%d",nonce);
    strcpy(textoPlano,"alice");
    strcat(textoPlano,",");
    strcat(textoPlano,cadenaNonce);
/*Here I am sending a message with my name and my nonce*/
    struct Encriptacion envio;
    printf(">Encrypting the autentication message...\n");
    sleep(1);
    envio.tamEn = public_encrypt(textoPlano,(int)strlen(textoPlano)+1,pub,envio.encrip);
    if(envio.tamEn == -1){
        printLastError("public encrypt\n");
        exit(1);
    }
    if(write(client_socket,&envio,sizeof(envio)) <0){
        printf("Error write");
        exit(-1);
    }

    printf(">Sending autentication message...\n");
    sleep(1);
    struct Encriptacion res;


    unsigned char decr[4096];
    int decr_length;
    printf(">Receiving autentication message...\n");
    if(read( client_socket, &res, sizeof(res)) == -1){
        printf("Error Read\n");
        exit(-1);
    }
    printf(">Decrypting the received autentication message...\n");
    decr_length = private_decrypt(res.encrip,res.tamEn,priv,decr);
    printf(">Decripted message: %s\n",decr);


    char delimitador[10]=",";
    char *nonce1 = strtok(decr,delimitador);
    char *nonce2 = strtok(NULL,delimitador);
    int comprobacion1, comprobacion2;
    int autenticado = 0;
    char returnNonce[MAXBUF];
    printf(">Taking out the nonces...\n");
    sleep(1);
    printf(">SUCCESS!\n");
    printf(">Comparing nonces to autenticate the partner...\n");
    if(atoi(nonce1) == nonce){
        autenticado = 1;
        strcpy(returnNonce,nonce2);
    }
    else if(atoi(nonce2) == nonce){
        autenticado = 1;
        strcpy(returnNonce,nonce1);
    }
    strcpy(textoPlano,"");
    strcpy(envio.encrip,"");
    envio.tamEn = 0;
    strcpy(decr,"");
    decr_length = 0;
    if(autenticado == 1){
        printf(">Autenticated, is right partner\n");
        printf(">Returning partner nonce...\n");
        strcpy(textoPlano,returnNonce);
        envio.tamEn = public_encrypt(textoPlano,(int)strlen(textoPlano)+1,pub,envio.encrip);
        if(write(client_socket,&envio,sizeof(envio)) == -1){
            printf("Error segundo envio\n");
            exit(-1);
        }
        printf(">Starting the chat operation, if you want finish it, do CTRL+C\n");
        char respuesta[2048/8];
        while(strcmp(textoPlano,"ENDCONNECTION") != 0){
            if(read( client_socket, respuesta, sizeof(char)*(2048/8)) == -1){
                printf("Error Read\n");
                exit(-1);
            }
            printf(">Server message: %s\n",respuesta);
            strcpy(respuesta,"");
            strcpy(textoPlano,"");
            printf(">Write your message: ");
            scanf(" %[^\n]s",textoPlano);
            printf(">Sending the message...\n");
            sleep(1);
            if(write(client_socket,&textoPlano,sizeof(textoPlano)) <0){
                printf("Error write");
                exit(-1);
            }
        }

    }
    else{
        close(client_socket);
    }
}