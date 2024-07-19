
#ifndef __HTTP_H__
#define __HTTP_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include <adlist.h>
#include <sds.h>

#define HTTP_LINE_END "\r\n"
#define HTTP_HEAD_END "\r\n\r\n"

#define HTTP_Content_Length "Content-Length"

typedef enum _http_status
{
    HTTP_STATUS_HEAD_VERIFY = 0x00,
    HTTP_STATUS_HEAD_PARSE,
    HTTP_STATUS_BODY_RECV,
    HTTP_STATUS_Max
}http_status;

typedef struct _http_header
{
    sds *key;
    sds *value;
}http_header;

typedef struct _http_response
{
    http_status status;

    //响应行.
    sds *versions;
    char code[6];
    sds *statments;

    //响应头.
    list * header_list;

    //响应体.
    sds * body;
    int body_len;
}http_response;

typedef struct _http_request
{
    http_status status;

    //请求行.
    sds *method;
    sds *uri;
    sds *versions;

    //请求头.
    list * header_list;

    //请求体.
    sds * body;
    int body_len;
}http_request;

/*
    http header functions.
*/
http_header *httpHeaderNew();
void httpHeaderFree(void *ptr);
int httpHeaderMatch(void *ptr, void *key);

bool httpHeadersOK(const sds*buf);
char *httpStatusName(http_status status);

/*  
    http request.
*/
http_request * httpRequestNew();
void httpRequestEmpty(http_request * req);
void httpRequestFree(http_request * req);

int httpRequestParse(const sds *buf,http_request *req);
void httpRequestPrint(const http_request *req);

http_status httpRequestStatusGet(const http_request *req);
void httpRequestStatusSet(http_request *req,http_status status);

bool httpRequestBodyOK(const http_request *req);

/*  
    http response.
*/
http_response * httpResponseNew();
void httpResponseEmpty(http_response * res);
void httpResponseFree(http_response * res);

int httpResponseParse(const sds *buf,http_response *res);
void httpResponsePrint(const http_response *res);

http_status httpResponseStatusGet(const http_response *res);
void httpResponseStatusSet(http_response *res,http_status status);

bool httpResponseBodyOK(const http_response *res);

#endif //__HTTP_H__
