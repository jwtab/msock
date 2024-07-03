
#ifndef __MODULE_S5_H__
#define __MODULE_S5_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <arpa/inet.h>

#include <net_inc.h>

#define SOCKS_VERSION 0x05
#define SOCKS_AUTH_VERSION 0x01

#define SOCKS_AUTH_OK 0x00
#define SOCKS_AUTH_ER 0x01

#define S5_USER_NAME "username"
#define S5_PASSWORD "123456"

/*
    定义socks5协议的三个阶段.
*/
typedef enum S5_Status
{
    S5_STATUS_HANDSHAKE_1 = 0,
    S5_STATUS_HANDSHAKE_2,
    S5_STATUS_REQUEST,
    S5_STATUS_RELAY,
    S5_STATUS_Max
}S5_STATUS;

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
typedef enum S5_AddressType 
{
    S5_AddressType_NONE = 0,
    S5_AddressType_IPv4,
    S5_AddressType_NONE2,
    S5_AddressType_DOMAINNAME,
    S5_AddressType_IPv6,
    S5_AddressType_Max
}S5_AddressType;

/*
    socks5 request type.
*/
typedef enum S5_RequestType
{
    S5_RequestType_NONE = 0,
    S5_RequestType_CONNECT,
    S5_RequestType_BIND,
    S5_RequestType_UDP,
    S5_RequestType_Max
}S5_RequestType;

typedef struct _s5_fds
{
    S5_STATUS status;
    S5_AUTH  auth_type;

    int fd_real_client;
    int fd_real_server;

    char client_version;
    char auth_version;

    //数据.
    char * buf;
    int alloc_len;
    int buf_len;

    unsigned long upstream_byte;
    unsigned long downstream_byte;

    //验证信息.
    char username[256];
    char password[256];

    //真实服务器.
    char real_host[256];
    short real_port;
}s5_fds;

s5_fds *s5FDsNew();
void s5FDsFree(s5_fds *s5);

char * s5StatusName(int status);
char * s5AuthTypeName(int auth_type);

void s5ClientMethods_Request(s5_fds *s5);
void s5ClientMethods_Response(s5_fds *s5);

void s5ClientAuthUP_Request(s5_fds *s5);
void s5ClientAuthUP_Response(s5_fds *s5);

void s5ClientRequest_Request(s5_fds *s5);
void s5ClientRequest_Response(struct aeEventLoop *eventLoop,aeFileProc *proc,s5_fds *s5);

void s5Relay(struct aeEventLoop *eventLoop,int fd,s5_fds *s5);

void s5Process(struct aeEventLoop *eventLoop,int fd,int mask,s5_fds *s5,aeFileProc *proc);

#endif //__MODULE_S5_H__
