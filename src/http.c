
#include <http.h>

#include <zmalloc.h>

char HTTP_STATUS_NAMES[HTTP_STATUS_Max][64] = {
    "HTTP_head_verify",
    "HTTP_head_parse",
    "HTTP_body_recv"
};

/*
    static functions.
*/

int _str_find(const char * str,int start_pos,char c)
{
    int end_pos = start_pos;
    while(str[end_pos] != c)
    {
        end_pos++;
    }

    return end_pos;
}

int _str_http_headers(const char *http_string,int start_pos,list *h_list)
{
    int end = start_pos;
    
    /*
        {KEY}:{values}\r\n
        ......\r\n
        \r\n
    */
    do
    {
        http_header *node = httpHeaderNew();
        
        end = _str_find(http_string,start_pos,':');
        sdsCatlen(node->key,http_string + start_pos,end - start_pos);
        start_pos = end + 1;

        while(' ' == http_string[start_pos])
        {
            start_pos++;
        }

        end = _str_find(http_string,start_pos,'\r');
        sdsCatlen(node->value,http_string + start_pos,end - start_pos);
        start_pos = end + 2;

        listAddNodeTail(h_list,node);

        if(0 == strncmp(HTTP_LINE_END,http_string + start_pos,2))
        {
            end = start_pos + 2;
            break;
        }
    } while (1);

    return end;
}

int _http_body_length(list *l)
{
    int len = -1;

    listNode * node = listFirst(l);
    while (NULL != node)
    {
        http_header * h = node->value;
        if(0 == strcasecmp(sdsPTR(h->key),HTTP_Content_Length))
        {
            len = atol(sdsPTR(h->value));

            break;
        }

        node = listNextNode(node);
    }
    
    return len;
}

/*
    http headers.
*/
http_header *httpHeaderNew()
{
    http_header * h = (http_header*)zmalloc(sizeof(http_header));
    if(NULL != h)
    {
        h->key = sdsCreateEmpty(32);
        h->value = sdsCreateEmpty(32);
    }

    return h;
}

void httpHeaderFree(void *ptr)
{
    http_header * h = (http_header*)ptr;
    if(h)
    {
        if(NULL != h->key)
        {
            sdsRelease(h->key);
            h->key = NULL;
        }

        if(NULL != h->value)
        {
            sdsRelease(h->value);
            h->value = NULL;
        }

        zfree(h);
        h = NULL;
    }
}

int httpHeaderMatch(void *ptr, void *key)
{
    http_header * h = (http_header*)ptr;
    char * value_key = key;

    return strcmp(sdsPTR(h->key),value_key);
}

/*
    判断http的头是否完整.
*/
bool httpHeadersOK(const sds*buf)
{
    bool verify_ = false;
    char * http_string = sdsPTR(buf);

    if(NULL != strstr(http_string,HTTP_HEAD_END))
    {
        verify_ = true;
    }

    return verify_;
}

char *httpStatusName(http_status status)
{
    return HTTP_STATUS_NAMES[status];
}

/*  
    http request.
*/
http_request * httpRequestNew()
{
    http_request * req = (http_request*)zmalloc(sizeof(http_request));
    if(NULL != req)
    {
        req->body = NULL;

        req->method = sdsCreateEmpty(6);
        req->uri = sdsCreateEmpty(128);
        req->versions = sdsCreateEmpty(16);

        req->header_list = listCreate();
        if(NULL != req->header_list)
        {
            listSetMatchMethod(req->header_list,httpHeaderMatch);
            listSetFreeMethod(req->header_list,httpHeaderFree);
        }

        req->status = HTTP_STATUS_HEAD_VERIFY;
        req->body_len = 0;
        req->body = sdsCreateEmpty(16);
    }

    return req;
}

void httpRequestEmpty(http_request * req)
{

}

void httpRequestFree(http_request * req)
{
    httpRequestEmpty(req);
}

/*
    POST /abc/edf HTTP/1.1
    {KEY}:{VALUE}
*/
int httpRequestParse(const sds *buf,http_request *req)
{
    int pos = 0;
    int end_pos = 0;
    char *http_string = sdsPTR(buf);

    end_pos = _str_find(http_string,pos,' ');
    sdsCatlen(req->method,http_string + pos,end_pos - pos);
    pos = end_pos + 1;

    end_pos = _str_find(http_string,pos,' ');
    sdsCatlen(req->uri,http_string + pos,end_pos - pos);
    pos = end_pos + 1;

    end_pos = _str_find(http_string,pos,'\r');
    sdsCatlen(req->versions,http_string + pos,end_pos - pos);
    pos = end_pos + 2;

    end_pos = _str_http_headers(http_string,pos,req->header_list);

    /*
        尝试解析body的长度，也可能没有.
    */
    req->body_len = _http_body_length(req->header_list);
    if(req->body_len > 0)
    {
        req->body = sdsCreateEmpty(req->body_len);

        sdsCatlen(req->body,http_string + end_pos,sdsLength(buf) - end_pos);
    }

    return end_pos;
}

void httpRequestPrint(const http_request *req)
{
    printf("[httpRequest] \r\n");
    printf("Method:%s\r\n",sdsString(req->method,0));
    printf("URI:%s\r\n",sdsString(req->uri,0));
    printf("Versions:%s\r\n",sdsString(req->versions,0));
    printf("\r\n");
    listNode * node = listFirst(req->header_list);
    while (NULL != node)
    {
        http_header * h = (http_header*)node->value;
        printf("%s:%s\r\n",sdsPTR(h->key),sdsPTR(h->value));

        node = listNextNode(node);
    }

    printf("[httpRequest] \r\n");
}

http_status httpRequestStatusGet(const http_request *req)
{
    return req->status;
}

void httpRequestStatusSet(http_request *req,http_status status)
{
    req->status = status;
}

bool httpRequestBodyOK(const http_request *req)
{
    if(req->body_len > 0)
    {
        if(sdsLength(req->body) >= req->body_len)
        {
            return true;
        }
    }
    
    return false;
}

/*  
    http response.
*/
http_response * httpResponseNew()
{
    http_response * res = (http_response*)zmalloc(sizeof(http_response));
    if(NULL != res)
    {
        res->body = NULL;

        res->versions = sdsCreateEmpty(16);
        memset(res->code,0,sizeof(res->code));
        res->statments = sdsCreateEmpty(32);

        res->header_list = listCreate();
        if(NULL != res->header_list)
        {
            listSetMatchMethod(res->header_list,httpHeaderMatch);
            listSetFreeMethod(res->header_list,httpHeaderFree);
        }

        res->status = HTTP_STATUS_HEAD_VERIFY;
        res->body_len = 0;
        res->body = sdsCreateEmpty(16);
    }

    return res;
}

void httpResponseEmpty(http_response * res)
{

}

void httpResponseFree(http_response * res)
{
    httpResponseEmpty(res);
}

/*
    HTTP/1.1 200 Connection Established
    Content-Type:
    Content-Length:36{uuid数据}

    {data}
*/
int httpResponseParse(const sds *buf,http_response *res)
{
    int pos = 0;
    int end_pos = 0;
    char *http_string = sdsPTR(buf);

    end_pos = _str_find(http_string,pos,' ');
    sdsCatlen(res->versions,http_string + pos,end_pos - pos);
    pos = end_pos + 1;

    end_pos = _str_find(http_string,pos,' ');
    memcpy(res->code,http_string + pos,end_pos - pos);
    pos = end_pos + 1;

    end_pos = _str_find(http_string,pos,'\r');
    sdsCatlen(res->statments,http_string + pos,end_pos - pos);
    pos = end_pos + 2;
    
    end_pos = _str_http_headers(http_string,pos,res->header_list);

    /*
        尝试解析body的长度，也可能没有.
    */
    res->body_len = _http_body_length(res->header_list);
    if(res->body_len > 0)
    {
        res->body = sdsCreateEmpty(res->body_len);

        sdsCatlen(res->body,http_string + end_pos,sdsLength(buf) - end_pos);
    }

    return end_pos;
}

void httpResponsePrint(const http_response *res)
{
    printf("[httpResponse] \r\n");
    printf("Versions:%s\r\n",sdsString(res->versions,0));
    printf("Code:%s\r\n",res->code);
    printf("Statments:%s\r\n",sdsString(res->statments,0));
    printf("\r\n");
    listNode * node = listFirst(res->header_list);
    while (NULL != node)
    {
        http_header * h = (http_header*)node->value;
        printf("%s:%s\r\n",sdsPTR(h->key),sdsPTR(h->value));

        node = listNextNode(node);
    }

    printf("[httpResponse] \r\n");
}

http_status httpResponseStatusGet(const http_response *res)
{
    return res->status;
}

void httpResponseStatusSet(http_response *res,http_status status)
{
    res->status = status;
}

bool httpResponseBodyOK(const http_response *res)
{
    if(res->body_len > 0)
    {
        if(sdsLength(res->body) >= res->body_len)
        {
            return true;
        }
    }
    else
    {
        //chunk模式.
    }

    return false;
}
