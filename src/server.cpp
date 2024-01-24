#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/rsa.h>     
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <pthread.h>

#define CERTF   "sm2.liyq.enc.crt.pem" /*服务端的证书(需经CA签名)*/
#define KEYF   "sm2.liyq.enc.key.pem"  /*服务端的私钥(建议加密存储)*/
#define CACERT "sm2.oca.pem" /*CA 的证书*/

#define SERVER_PORT  10088   
#define SERVER_ADDR "182.92.205.179"

typedef struct CONN_SOCKET{
    int conSocket;
    SSL* sslSocket;
}ConnSocket;


ConnSocket connSocket[1024] = {0};

void *threadFunc(void* connSocket){

    ConnSocket* pConnSocket = (ConnSocket*)connSocket;

    /*打印所有加密算法的信息(可选)*/
    printf ("[%d] SSL connection using %s\n", getpid(), SSL_get_cipher(pConnSocket->sslSocket));
    
    char recvBuf[1024 * 100] = {0};  
    char sendBuf[1024 * 100] = {0};
    while(1){
        int iLength = SSL_read(pConnSocket->sslSocket, recvBuf, sizeof(recvBuf) - 1);  
        if(iLength == -1){
            ERR_print_errors_fp(stderr);
            break;
        }else if(iLength == 0){
 	        printf("[%d] read size 0\n", getpid());	
            break;	
        }

        printf ("[%d] SSL_read size = %d\n", getpid(), iLength);
        printf ("%s", recvBuf);
        memset(recvBuf, 0, sizeof(recvBuf));

	printf("\n");

        sprintf(sendBuf, "HTTP/1.0 200 OK\r\n");
        SSL_write (pConnSocket->sslSocket, sendBuf, strlen(sendBuf));
        memset(sendBuf, 0, sizeof(sendBuf));


        sprintf(sendBuf, "\r\n");
        SSL_write (pConnSocket->sslSocket, sendBuf, strlen(sendBuf));
        memset(sendBuf, 0, sizeof(sendBuf));

        sprintf(sendBuf, "<html>\r\n");
        SSL_write (pConnSocket->sslSocket, sendBuf, strlen(sendBuf));
        memset(sendBuf, 0, sizeof(sendBuf));
        
	    sprintf(sendBuf, "<head>\r\n");
        SSL_write (pConnSocket->sslSocket, sendBuf, strlen(sendBuf));
        memset(sendBuf, 0, sizeof(sendBuf));
	
	    sprintf(sendBuf, "<title>GMSSL</title>\r\n");
        SSL_write (pConnSocket->sslSocket, sendBuf, strlen(sendBuf));
        memset(sendBuf, 0, sizeof(sendBuf));

	    sprintf(sendBuf, "<h1>GMSSL WEB</h1>\r\n");
        SSL_write (pConnSocket->sslSocket, sendBuf, strlen(sendBuf));
        memset(sendBuf, 0, sizeof(sendBuf));
	
	    sprintf(sendBuf, "<p>welcome to gmssl web</p>\r\n");
        SSL_write (pConnSocket->sslSocket, sendBuf, strlen(sendBuf));
        memset(sendBuf, 0, sizeof(sendBuf));
	
	    sprintf(sendBuf, "</body>\r\n");
        SSL_write (pConnSocket->sslSocket, sendBuf, strlen(sendBuf));
        memset(sendBuf, 0, sizeof(sendBuf));
	
	    sprintf(sendBuf, "</html>\r\n");
        SSL_write (pConnSocket->sslSocket, sendBuf, strlen(sendBuf));
        memset(sendBuf, 0, sizeof(sendBuf));
    }

    close(pConnSocket->conSocket);
    SSL_shutdown(pConnSocket->sslSocket);
    SSL_free(pConnSocket->sslSocket);

    return NULL;
}


int main (){
    SSL_load_error_strings();            /*为打印调试信息作准备*/
    OpenSSL_add_ssl_algorithms();        /*初始化*/

    const SSL_METHOD *method = GMSSLv1_1_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if(ctx == NULL) {
        printf("SSL_CTX_new failed.\n");
        return -1;
    }

    //SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);   /*是否验证客户端证书，双向认证时开启*/
    //SSL_CTX_load_verify_locations(ctx,CACERT,NULL); /*若验证,则放置CA证书*/

    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        printf("Private key does not match the certificate public key\n");
        return -1;
    }

    //SSL_CTX_set_cipher_list(ctx,"ECC-SM4-GCM-SM3"); 
    SSL_CTX_set_cipher_list(ctx, "ALL"); 

    /*开始正常的TCP socket过程.*/
    printf("Begin TCP socket...\n");

    int listenSock = socket(AF_INET, SOCK_STREAM, 0);  
    if(listenSock == -1){
        perror("socket");
        return -1;
    }

    struct sockaddr_in sa_serv;
    memset (&sa_serv, 0, sizeof(sa_serv));
    sa_serv.sin_family = AF_INET;
    //sa_serv.sin_addr.s_addr = inet_addr(SERVER_ADDR);
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    
    sa_serv.sin_port = htons(SERVER_PORT);         

    if(bind(listenSock, (struct sockaddr*) &sa_serv, sizeof (sa_serv)) == -1){
        perror("bind");
        return -1;
    }

    /*接受TCP链接*/
    if(listen (listenSock, 5) == -1){
        perror("listen");
        return -1;
    }                   

    struct sockaddr_in sa_cli;
    socklen_t client_len = sizeof(sa_cli);

    int index = 0;
    pthread_t tid[1024] = {0};

    while(1){
        connSocket[index].conSocket = accept (listenSock, (struct sockaddr*) &sa_cli, &client_len);
        if(connSocket[index].conSocket == -1){
            perror("accept");
            close (listenSock);
            return -1;
        }

        printf ("[%s:%d] connected...\n", inet_ntoa(sa_cli.sin_addr), sa_cli.sin_port);

        connSocket[index].sslSocket = SSL_new (ctx);
        if(connSocket[index].sslSocket == NULL){
            printf("SSL_new failed.\n");
            close (listenSock);
            return -1;
        }
        SSL_set_fd (connSocket[index].sslSocket, connSocket[index].conSocket);

        int sslAccept = SSL_accept (connSocket[index].sslSocket);
        if(sslAccept == -1){
            ERR_print_errors_fp(stderr);
            close (listenSock);
            return -1;
        }

        tid[index] = pthread_create(&tid[index], NULL, threadFunc, (void*)&connSocket[index]);
	    index++;
    }

    close (listenSock);
    SSL_CTX_free (ctx);
    return 0;
}
