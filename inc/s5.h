
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
}S5_StATUS;

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

typedef struct _s5_fds
{
    int fd_real_client;
    int fd_real_server;

    S5_StATUS status;
    S5_AUTH  auth;

    //数据.
    char * buf;
    int buf_len;

    //验证信息
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

void s5ClientMethods(const char * data);
void s5ClientUNamePwd(const char * data,s5_fds *s5);
void s5ClientRequest(const char * data,s5_fds *s5);

void s5Process(struct aeEventLoop *eventLoop,int fd,int mask,s5_fds *s5,aeFileProc *proc);

#endif //__MODULE_S5_H__
