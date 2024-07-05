
#ifndef __MODULE_SSR_H__
#define __MODULE_SSR_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

/*
    ssr的版本.
*/
#define SSR_VERSION_0x10 0x10
#define SSR_VERSION_0x20 0x20

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
    SSR_TYPE_AUTH    = 0x20,
    SSR_TYPE_CONNECT,
    SSR_TYPE_DATA,
    SSR_TYPE_Max
}SSR_TYPE;

/*
    ssr的扩展header.
*/
#define SSR_HEADER_VER  "SSR_VER"
#define SSR_HEADER_TYPE "SSR_TYPE"

#define SSR_HEAD_HOST "ssr.google.com"

char * httpMethodName(HTTP_METHOD method);

char * ssrTypeName(SSR_TYPE type);

void ssrAuth_Request(int fd,const char * username,const char * password);
void ssrAuth_Response(int fd);

void ssrConnect_Request(int fd);
void ssrConnect_Response(int fd);

void ssrRelay();

#endif //__MODULE_SSR_H__
