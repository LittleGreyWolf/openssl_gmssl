#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_PORT  10088   
#define SERVER_ADDR "182.92.205.179"

//#define SERVER_PORT  1443   
//#define SERVER_ADDR "114.242.62.34"

#define MAXBUF 1024 * 100

int main(int argc, char *argv[])
{
    struct sockaddr_in serveraddr;
    int length = 0;
    SSL *ssl = NULL;

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // GM create CTX
    const SSL_METHOD *method = GMSSLv1_1_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) 
    {
        printf("create ctx is failed.\n");
        return -1;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    bzero(&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = inet_addr(SERVER_ADDR);
    serveraddr.sin_port  = htons(SERVER_PORT);
    
    int retC = connect(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    if(retC != 0)
    {
        printf("connnect failed\n");
        SSL_CTX_free(ctx);
        return -1;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("SSL_new error.\n");
        return -1;
    }
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) == -1) {
        printf("SSL_connect fail.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    else {
	printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    }

    printf("------------send-------\n"); 
    char sendBuf[MAXBUF] = { 0 };
    strcpy(sendBuf, "GET / HTTP/1.1\r\n");
    SSL_write(ssl, sendBuf, strlen(sendBuf));
    printf("%s", sendBuf);
    memset(sendBuf, 0, sizeof(sendBuf));

    strcpy(sendBuf, "\r\n");
    SSL_write(ssl, sendBuf, strlen(sendBuf));
    printf("%s", sendBuf);
    memset(sendBuf, 0, sizeof(sendBuf));
    
    strcpy(sendBuf, "Accept: */*\r\n");
    SSL_write(ssl, sendBuf, strlen(sendBuf));
    printf("%s", sendBuf);
    memset(sendBuf, 0, sizeof(sendBuf));

    strcpy(sendBuf, "Accept-Encoding: gzip, deflate, br\r\n");
    SSL_write(ssl, sendBuf, strlen(sendBuf));
    printf("%s", sendBuf);
    memset(sendBuf, 0, sizeof(sendBuf));
    
    strcpy(sendBuf, "Accept-Language: zh-CN,zh;1=0.9\r\n");
    SSL_write(ssl, sendBuf, strlen(sendBuf));
    printf("%s", sendBuf);
    memset(sendBuf, 0, sizeof(sendBuf));
   
    strcpy(sendBuf, "Cache-Control: no-cache\r\n");
    SSL_write(ssl, sendBuf, strlen(sendBuf));
    printf("%s", sendBuf);
    memset(sendBuf, 0, sizeof(sendBuf));

    strcpy(sendBuf, "Connection: keep-alive\r\n");
    SSL_write(ssl, sendBuf, strlen(sendBuf));
    printf("%s", sendBuf);
    memset(sendBuf, 0, sizeof(sendBuf));

    sprintf(sendBuf, "Host: %s:%d\r\n", SERVER_ADDR, SERVER_PORT);
    SSL_write(ssl, sendBuf, strlen(sendBuf));
    printf("%s", sendBuf);
    memset(sendBuf, 0, sizeof(sendBuf));
   
    strcpy(sendBuf, "Upgrade-Insecure-Requests: 1\r\n");
    SSL_write(ssl, sendBuf, strlen(sendBuf));
    printf("%s", sendBuf);
    memset(sendBuf, 0, sizeof(sendBuf));
    
    strcpy(sendBuf, "User-Agent: Chrome/102.0.5005.200\r\n");
    SSL_write(ssl, sendBuf, strlen(sendBuf));
    printf("%s", sendBuf);
    memset(sendBuf, 0, sizeof(sendBuf));
    
    printf("------------recv-------\n"); 
    char recvBuf[MAXBUF] = {0};
    length = SSL_read(ssl, recvBuf, MAXBUF);
    if (length > 0) {
        printf("read size is %d\n", length);
        printf("%s\n", recvBuf);
    }
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}
