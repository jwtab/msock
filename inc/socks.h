
#ifndef __MODULE_S5_H__
#define __MODULE_S5_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <arpa/inet.h>

#include <net_inc.h>
#include <sds.h>
#include <http.h>

#define SOCKS_VERSION_4  0x04
#define SOCKS_VERSION_4A 0x14
#define SOCKS_VERSION_5  0x05

#define SOCKS_AUTH_VERSION 0x01

#define SOCKS5_AUTH_OK 0x00
#define SOCKS5_AUTH_ER 0x01

#define SOCKS4_AUTH_5A 0x5a
#define SOCKS4_AUTH_5B 0x5b
#define SOCKS4_AUTH_5C 0x5c
#define SOCKS4_AUTH_5D 0x5d

#define SOCKS_BUF_SIZE 2048

#define S5_USER_NAME "username"
#define S5_PASSWORD "123456"

/*
    定义socks协议的阶段.
*/
typedef enum SOCKS_Status
{
    SOCKS_STATUS_HANDSHAKE_1 = 0,
    SOCKS_STATUS_HANDSHAKE_2,
    SOCKS_STATUS_REQUEST,
    SOCKS_STATUS_RELAY,
    SOCKS_STATUS_Max
}SOCKS_STATUS;

/*
    定义支持的认证方式.
*/
typedef enum S5_Auth
{
    S5_AUTH_NONE = 0x00,
    S5_AUTH_GSSAPI,
    S5_AUTH_USERNAME_PASSWORD,
    S5_AUTH_Max
}S5_AUTH;

/*
    定义地址类型.
*/
typedef enum SOCKS_AddressType 
{
    SOCKS_AddressType_NONE = 0,
    SOCKS_AddressType_IPv4,
    SOCKS_AddressType_NONE2,
    SOCKS_AddressType_DOMAINNAME,
    SOCKS_AddressType_IPv6,
    SOCKS_AddressType_Max
}SOCKS_AddressType;

/*
    socks request type.
*/
typedef enum SOCKS_RequestType
{
    S5_RequestType_NONE = 0,
    S5_RequestType_CONNECT,
    S5_RequestType_BIND,
    S5_RequestType_UDP,
    S5_RequestType_Max
}SOCKS_RequestType;

typedef struct _s5_fds
{
    SOCKS_STATUS status;
    S5_AUTH  auth_type;

    int fd_real_client;
    int fd_real_server;

    void * ssl;
    http_response * res;
    
    char client_version;
    char auth_version;

    //数据.
    sds * buf;

    unsigned long upstream_byte;
    unsigned long downstream_byte;

    //真实服务器.
    char real_host[256];
    short real_port;

    //认证信息.
    char username[64];
    char password[64];
}s5_fds;

s5_fds *s5FDsNew();
void s5FDsFree(s5_fds *s5);

void sockProxy_data(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);
void sockProxy_accept(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);

char * s5StatusName(int status);
char * s5AuthTypeName(int auth_type);

void s5ClientMethods_Request(s5_fds *s5);
void s5ClientMethods_Response(s5_fds *s5);

void s5ClientAuthUP_Request(s5_fds *s5);
void s5ClientAuthUP_Response(s5_fds *s5);

void s5ClientRequest_Request(s5_fds *s5);
void s5ClientRequest_Response(struct aeEventLoop *eventLoop,s5_fds *s5);

void s4ClientRequest_Request(s5_fds *s5);
void s4ClientRequest_Response(struct aeEventLoop *eventLoop,s5_fds *s5);

void socksRelay_local(struct aeEventLoop *eventLoop,int fd,s5_fds *s5);

void socksProcess(struct aeEventLoop *eventLoop,int fd,int mask,s5_fds *s5);

#endif //__MODULE_S5_H__
