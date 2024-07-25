
#ifndef __MODULE_SSR_H__
#define __MODULE_SSR_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <net_main.h>

/*
    ssr的版本.
*/
#define SSR_VERSION_0x01 0x01
#define SSR_VERSION_0x02 0x02

#define SSR_URL "/msock/data"

/*
    http的方法.
*/
typedef enum _http_method {
    HTTP_METHOD_GET = 0,
    HTTP_METHOD_POST,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_Max
}HTTP_METHOD;

/*
    http结束符号.
*/
#define HTTP_LINE_END "\r\n"
#define HTTP_HEAD_END "\r\n\r\n"

/*
    定义ssr协议类型.
*/
typedef enum _ssr_type {
    SSR_TYPE_AUTH    = 0x00,
    SSR_TYPE_CONNECT,
    SSR_TYPE_DATA,
    SSR_TYPE_Max
}SSR_TYPE;

/*
    ssr的扩展header.
*/
#define SSR_HEADER_VER  "SSR_VER"
#define SSR_HEADER_TYPE "SSR_TYPE"

#define SSR_HEAD_HOST "msock.dxlogin.com"

/*
    SSR 协议函数.
*/
char * httpMethodName(HTTP_METHOD method);

char * ssrTypeName(SSR_TYPE type);

/*
*/
int ssrAuth_Request(SSL *ssl,const char * username,const char * password);
int ssrAuth_Response(SSL *ssl,const char * data);

int ssrConnect_Request(SSL *ssl,const char *hostname,short port);
int ssrConnect_Response(SSL *ssl,bool ok);

int ssrData_Request(SSL *ssl,const char * data,int len);
int ssrData_Response(SSL *ssl,const char * data,int len);

int ssrFake_html(SSL *ssl,const char *data,int len);

#endif //__MODULE_SSR_H__
