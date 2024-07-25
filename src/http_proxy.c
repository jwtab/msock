
#include <unistd.h>
#include <errno.h>
#include <http_proxy.h>
#include <ssr.h>

#include <zmalloc.h>
#include <net_inc.h>
#include <net_main.h>
#include <mlog.h>

char HTTP_PROXY_STATUS_NAMES[HTTP_PROXY_STATUS_Max][64] = {
    "HTTP_CONNECT",
    "HTTP_RELAY",
};

/*
    CONNECT hostname:port HTTP/1.1 \r\n
*/
static void _httpProxy_real_destination(char * data,int buf_len,char *host,short *port)
{
    int start_pos = 0;
    int end_pos = 0;
    char value[64] = {0};

    start_pos = strlen(HTTP_PROXY_CONNECT);

    do
    {
        if(' ' != data[start_pos])
        {
            break;
        }
        else
        {
            start_pos++;
        }
    } while (1);
        
    end_pos = start_pos;
    do
    {
        if(':' == data[end_pos])
        {
            break;
        }
        else
        {
            end_pos++;
        }
    } while (1);

    memcpy(host,data + start_pos,end_pos - start_pos);

    start_pos = end_pos + 1;
    do
    {
        if(' ' == data[end_pos])
        {
            break;
        }
        else
        {
            end_pos++;
        }
    } while (1);

    memcpy(value,data + start_pos,end_pos - start_pos);

    *port = atoi(value);
}

/*
    ......
    Proxy-Authorization: Basic dXNlcm5hbWU6MTIzNDU2 \r\n
    ......
*/
static void _httpProxy_auth(char * data,int buf_len,char *username,char *password)
{
    int start_pos = 0;
    int end_pos = 0;
    char value[128] = {0};

    char *found = strstr(data,HTTP_HEADER_PROXY_AUTH);
    if(NULL == found)
    {
        printf("_httpProxy_auth() NO AUTH DATA\r\n");

        return;
    }

    start_pos = strlen(HTTP_HEADER_PROXY_AUTH) + 1;
    do
    {
        if(' ' != found[start_pos])
        {
            break;
        }
        else
        {
            start_pos++;
        }
    } while (1);
    
    end_pos = start_pos;
    do
    {
        if(' ' == found[end_pos])
        {
            break;
        }
        else
        {
            end_pos++;
        }
    } while (1);

    memcpy(value,found + start_pos,end_pos - start_pos);
    printf("_httpProxy_auth() type %s\r\n",value);

    start_pos = end_pos;
    do
    {
        if(' ' != found[start_pos])
        {
            break;
        }
        else
        {
            start_pos++;
        }
    } while (1);
    
    end_pos = start_pos;
    do
    {
        if('\r' == found[end_pos])
        {
            break;
        }
        else
        {
            end_pos++;
        }
    } while (1);

    memcpy(value,found + start_pos,end_pos - start_pos);
    printf("_httpProxy_auth() data %s\r\n",value);

    strcpy(username,"username");
    strcpy(password,"123456");
}

char * httpProxyStatusName(int status)
{
    return HTTP_PROXY_STATUS_NAMES[status];
}

http_fds *httpFDsNew()
{
    http_fds *http = zmalloc(sizeof(http_fds));
    if(NULL != http)
    {
        memset(http,0,sizeof(http_fds));

        http->buf = sdsCreateEmpty(HTTP_PROXY_BUF_SIZE);
        http->res = httpResponseNew();

        http->fd_real_client = -1;
        http->fd_real_server = -1;

        http->ssl = NULL;

        #ifdef HTTP_PROXY_LOCAL
            http->proxy_type = PROXY_TYPE_LOCAL;
        #else
            http->proxy_type = PROXY_TYPE_SSR;
        #endif 
    }

    return http;
}

void httpFDsFree(http_fds *http)
{
    if(NULL != http)
    {
        httpResponseFree(http->res);

        if(NULL != http->ssl)
        {
            anetSSLClose(http->ssl);
            http->ssl = NULL;
        }

        if(NULL != http->buf)
        {
            sdsRelease(http->buf);
            http->buf = NULL;
        }

        if(http->fd_real_client > 0)
        {
            close(http->fd_real_client);
            http->fd_real_client = -1;
        }

        if(http->fd_real_server > 0)
        {
            close(http->fd_real_server);
            http->fd_real_server = -1;
        }

        zfree(http);
        http = NULL;
    }
}

/*
    CONNECT hostname:port HTTP/1.1 \r\n
    Host:hostname:port\r\n
    User-Agent:{UA}\r\n
    Proxy-Connection:...\r\n
    \r\n
*/
void httpCONNECT_Request(http_fds *http)
{
    if(0 == strncasecmp(HTTP_PROXY_CONNECT,sdsPTR(http->buf),strlen(HTTP_PROXY_CONNECT)))
    {
        ///printf("httpCONNECT_Request():%s\r\n",http->buf);

        _httpProxy_real_destination(sdsPTR(http->buf),sdsLength(http->buf),http->real_host,&http->real_port);
        printf("httpCONNECT_Request() try_connect_destination %s:%d\r\n",http->real_host,http->real_port);

        _httpProxy_auth(sdsPTR(http->buf),sdsLength(http->buf),http->username,http->password);
        if(0 != strlen(http->username) || 0 != strlen(http->password))
        {
            printf("httpCONNECT_Request() AUTH %s:%s\r\n",http->username,http->password);
        }
    }
    else
    {
        http->real_port = 0;

        printf("httpCONNECT_Request() %s \r\n",sdsPTR(http->buf));
    }
}

/*
    HTTP/1.1 200 Connection Established\r\n\r\n
*/
void httpCONNECT_Response(struct aeEventLoop *eventLoop,http_fds *http)
{
    sdsEmpty(http->buf);

    //判断hostname走ssr还是本地直接连接.

    if(PROXY_TYPE_LOCAL == http->proxy_type)
    {
        HttpCONNECT_Response_local(eventLoop,http);
    }
    else if(PROXY_TYPE_SSR == http->proxy_type)
    {
        HttpCONNECT_Remote_ssr(eventLoop,http);
    }
    else
    {

    }
}

bool HttpCONNECT_Response_local(struct aeEventLoop *eventLoop,http_fds *http)
{
    char err_str[ANET_ERR_LEN] = {0};

    http->fd_real_server = anetTcpNonBlockConnect(err_str,http->real_host,http->real_port);
    if(http->fd_real_server > 0)
    {
        anetNonBlock(err_str,http->fd_real_server);

        anetRecvTimeout(err_str,http->fd_real_server,SOCKET_RECV_TIMEOUT);
        anetSendTimeout(err_str,http->fd_real_server,SOCKET_SEND_TIMEOUT);

        printf("HttpCONNECT_Response_local() real_client_fd %d\r\n",http->fd_real_client);
        printf("HttpCONNECT_Response_local() real_server_fd %d\r\n",http->fd_real_server);

        if(AE_OK != aeCreateFileEvent(eventLoop,http->fd_real_server,AE_READABLE,httpProxy_proxy,http))
        {
            printf("HttpCONNECT_Response_local() aeCreateFileEvent(%d) error %d\r\n",http->fd_real_server,errno);
        }

        sdsCat(http->buf,HTTP_PROXY_RET_200);
        sdsCat(http->buf,HTTP_PROXY_BODY_END);
    }
    else
    {
        sdsCat(http->buf,HTTP_PROXY_RET_502);
        sdsCat(http->buf,HTTP_PROXY_BODY_END);

        printf("HttpCONNECT_Response_local(%s:%d) error %s \r\n",http->real_host,http->real_port,err_str);
    }
    
    http->status = HTTP_PROXY_STATUS_RELAY;
    anetWrite(http->fd_real_client,sdsPTR(http->buf),sdsLength(http->buf));

    return true;
}

bool HttpCONNECT_Remote_ssr(struct aeEventLoop *eventLoop,http_fds *http)
{
    char err_str[ANET_ERR_LEN] = {0};
    bool connected_ssr = true;

    http->fd_real_server = anetTcpNonBlockConnect(err_str,SSR_HOST,SSR_PORT);
    if(http->fd_real_server > 0)
    {
        http->ssl = anetSSLConnect(err_str,http->fd_real_server);
        if(NULL != http->ssl)
        {
            anetNonBlock(err_str,http->fd_real_server);
            anetRecvTimeout(err_str,http->fd_real_server,SOCKET_RECV_TIMEOUT);
            anetSendTimeout(err_str,http->fd_real_server,SOCKET_SEND_TIMEOUT);

            printf("HttpCONNECT_Remote_ssr() real_client_fd %d\r\n",http->fd_real_client);
            printf("HttpCONNECT_Remote_ssr() real_server_fd %d\r\n",http->fd_real_server);

            if(AE_OK != aeCreateFileEvent(eventLoop,http->fd_real_server,AE_READABLE,httpProxy_ssr,http))
            {
                printf("HttpCONNECT_Remote_ssr() aeCreateFileEvent(%d) error %d\r\n",http->fd_real_server,errno);
            }

            http->upstream_byte = http->upstream_byte + ssrConnect_Request(http->ssl,http->real_host,http->real_port);
            ///printf("HttpCONNECT_Remote_ssr() ssrConnect_Request() \r\n");
        }
        else
        {
            connected_ssr = false;
            printf("HttpCONNECT_Remote_ssr() anetSSLConnect(%s,%d) error %s\r\n",SSR_HOST,SSR_PORT,err_str);
        }
    }
    else
    {
        connected_ssr = false;
        printf("HttpCONNECT_Remote_ssr() anetTcpNonBlockConnect(%s:%d) error %s \r\n",SSR_HOST,SSR_PORT,err_str);
    }

    if(!connected_ssr)
    {
        sdsEmpty(http->buf);

        sdsCat(http->buf,HTTP_PROXY_RET_502);
        sdsCat(http->buf,HTTP_PROXY_BODY_END);

        http->status = HTTP_PROXY_STATUS_RELAY;
        anetWrite(http->fd_real_client,sdsPTR(http->buf),sdsLength(http->buf));
    }

    return true;
}

void httpRelay_local(struct aeEventLoop *eventLoop,int fd,http_fds *http)
{
    int fd_read = fd;
    int fd_write = 0;
    int nsended = 0;
    int upstream = 0;
    int len = 0;
    char buf[HTTP_PROXY_BUF_SIZE] = {0};

    if(fd_read == http->fd_real_client)
    {
        upstream = 1;
        fd_write = http->fd_real_server;
    }
    else
    {
        upstream = 0;
        fd_write = http->fd_real_client;
    }

    len = anetRead(fd_read,buf,HTTP_PROXY_BUF_SIZE);
    if(len > 0)
    {
        printf("httpRelay_local() anetRead(fd_[%d]) len %d\r\n",fd_read,len);
        nsended = anetWrite(fd_write,buf,len);
        if(len != nsended)
        {
            printf("httpRelay_local() wirte(fd_[%d]) len %d,errno %d\r\n",fd_write,nsended,errno);
        }
        else
        {
            ///printf("httpRelay_local() wirte(fd_[%d]) len %d\r\n",fd_write,http->buf_len);
        }

        if(upstream > 0)
        {
            http->upstream_byte = http->upstream_byte + nsended;
        }
        else
        {
            http->downstream_byte = http->downstream_byte + nsended;
        }
    }
    else
    {
        if(0 == len)
        {
            printf("httpRelay_local() fd_%d closed\r\n",fd);

            aeDeleteFileEvent(eventLoop,fd_read,AE_READABLE);
            aeDeleteFileEvent(eventLoop,fd_write,AE_READABLE);

            printf("httpRelay_local() session upstream_byte %ld,downstream_byte %ld\r\n",http->upstream_byte,http->downstream_byte);

            httpFDsFree(http);
            http = NULL;
        }
        else
        {
            printf("httpRelay_local() fd_%d errno %d\r\n",fd,errno);
        }   
    }
}

void httpRelay_ssr(struct aeEventLoop *eventLoop,http_fds *http)
{
    char buf[HTTP_PROXY_BUF_SIZE] = {0};
    int len = 0;

    printf("\r\n");

    len = anetRead(http->fd_real_client,buf,HTTP_PROXY_BUF_SIZE);
    if(len > 0)
    {
        printf("httpRelay_ssr() read_from_fd_%d len %d\r\n",http->fd_real_client,len);
        http->upstream_byte =  http->upstream_byte + ssrData_Request(http->ssl,buf,len);
    }
    else if(0 == len)
    {
        printf("httpRelay_ssr(ms:%ld) fd_%d closed errno %d.\r\n",mlogTick_ms(),http->fd_real_client,errno);

        aeDeleteFileEvent(eventLoop,http->fd_real_client,AE_READABLE);
        aeDeleteFileEvent(eventLoop,http->fd_real_server,AE_READABLE);

        printf("httpRelay_ssr() session upstream_byte %ld,downstream_byte %ld\r\n",http->upstream_byte,http->downstream_byte);

        httpFDsFree(http);
        http = NULL;
    }
}

void httpProxy_accept(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    char err_str[ANET_ERR_LEN] = {0};
    char ip[128] = {0};
    int port = 0;
    int fd_client = -1;

    fd_client = anetTcpAccept(err_str,fd,ip,128,&port);
    if(fd_client <= 0)
    {
        printf("httpProxy_accept() anetTcpAccept() error %s\r\n",err_str);
        return;
    }

    printf("httpProxy_accept() anetTcpAccept() %s:%d by fd_%d \r\n",ip,port,fd_client);

    //增加数据处理函数.
    http_fds *http = httpFDsNew();
    if(NULL != http)
    {
        http->fd_real_client = fd_client;
        http->fd_real_server = -1;
        http->status = HTTP_PROXY_STATUS_CONNECT;

        anetNonBlock(err_str,fd_client);
        
        anetRecvTimeout(err_str,fd_client,SOCKET_RECV_TIMEOUT);
        anetSendTimeout(err_str,fd_client,SOCKET_SEND_TIMEOUT);

        if(AE_OK != aeCreateFileEvent(eventLoop,fd_client,AE_READABLE,httpProxy_proxy,http))
        {
            printf("httpProxy_accept() aeCreateFileEvent(%d) errno %d\r\n",fd_client,errno);
        }
    }
}

void httpProxy_proxy(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    char buf[HTTP_PROXY_BUF_SIZE] = {0};
    int len = 0;

    http_fds *http = (http_fds*)clientData;
    if(mask&AE_READABLE)
    {
        if(HTTP_PROXY_STATUS_CONNECT == http->status)
        {
            len = anetRead(fd,buf,HTTP_PROXY_BUF_SIZE);
            if(len >= 2)
            {
                sdsCatlen(http->buf,buf,len);
                httpCONNECT_Request(http);
                if(0 == http->real_port)
                {
                    http->status = HTTP_PROXY_STATUS_RELAY;
                }
                else
                {
                    httpCONNECT_Response(eventLoop,http);
                }
            }
            else if(0 == len)
            {
                printf("httpProcess() socket(%d) closed\r\n",fd);

                aeDeleteFileEvent(eventLoop,fd,AE_READABLE);
                aeDeleteFileEvent(eventLoop,http->fd_real_server,AE_READABLE);

                httpFDsFree(http);
                http = NULL;
            }
        }
        else if(HTTP_PROXY_STATUS_RELAY == http->status)
        {
            if(PROXY_TYPE_LOCAL == http->proxy_type)
            {
                httpRelay_local(eventLoop,fd,http);
            }
            else if(PROXY_TYPE_SSR == http->proxy_type)
            {
                httpRelay_ssr(eventLoop,http);
            }
            else
            {
                
            }
        }
    }
}

void httpProxy_ssr(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask)
{
    http_fds * http = (http_fds*)clientData;
    http_status status = httpResponseStatusGet(http->res);
    char buf[HTTP_PROXY_BUF_SIZE] = {0};
    int len = 0;

    if(mask&AE_READABLE)
    {
        len = anetSSLRead(http->ssl,buf,HTTP_PROXY_BUF_SIZE);
        if(len > 0)
        {
            http->downstream_byte = http->downstream_byte + len;
            
            if(HTTP_STATUS_HEAD_VERIFY == status ||
                HTTP_STATUS_HEAD_PARSE == status)
            {
                printf("httpProxy_ssr() http_response_recv{head} ...\r\n");

                sdsCatlen(http->buf,buf,len);
                if(httpHeadersOK(http->buf))
                {
                    printf("httpProxy_ssr() http_response_recv{head} OK\r\n");

                    httpResponseParse(http->buf,http->res);
                    
                    ///httpResponsePrint(http->res);

                    httpResponseStatusSet(http->res,HTTP_STATUS_BODY_RECV);

                    if(httpResponseBodyOK(http->res))
                    {
                        printf("httpProxy_ssr() http_response_recv{body} OK\r\n");
                        proxyProc_fun(http,eventLoop);
                    }
                }
            }
            else if(HTTP_STATUS_BODY_RECV == status)
            {
                printf("httpProxy_ssr() http_request_recv{body} ...\r\n");
                sdsCatlen(http->res->body,buf,len);
                
                if(httpResponseBodyOK(http->res))
                {
                    printf("httpProxy_ssr() http_request_recv{body} OK\r\n");
                    proxyProc_fun(http,eventLoop);
                }
            }
        }
        else if(0 == len)
        {
            printf("httpProxy_ssr() socket(%d) close.",fd);

            aeDeleteFileEvent(eventLoop,http->fd_real_server,AE_READABLE|AE_WRITABLE);
            aeDeleteFileEvent(eventLoop,http->fd_real_server,AE_READABLE|AE_WRITABLE);

            httpFDsFree(http);
            http = NULL;
        }
    }
}

int _ssr_ask_response_type(http_response *res)
{
    int ask_type = -1;

    listNode *node = listFirst(res->header_list);
    while(NULL != node)
    {
        http_header *h = (http_header*)node->value;
        if(0 == strcasecmp(sdsPTR(h->key),SSR_HEADER_TYPE))
        {
            return atoi(sdsPTR(h->value));
        }

        node = listNextNode(node);
    }

    return ask_type;
}

void proxyProc_fun(http_fds *node,struct aeEventLoop *eventLoop)
{
    int ssr_type = _ssr_ask_response_type(node->res);
    switch(ssr_type)
    {
        case SSR_TYPE_AUTH:
        {
            printf("proxyProc_fun() SSR_TYPE_AUTH\r\n");
            break;
        }

        case SSR_TYPE_CONNECT:
        {
            printf("proxyProc_fun() SSR_TYPE_CONNECT response\r\n");

            sdsEmpty(node->buf);
            sdsCat(node->buf,HTTP_PROXY_RET_200);
            sdsCat(node->buf,HTTP_PROXY_BODY_END);
    
            node->status = HTTP_PROXY_STATUS_RELAY;
            anetWrite(node->fd_real_client,sdsPTR(node->buf),sdsLength(node->buf));

            break;
        }

        case SSR_TYPE_DATA:
        {
            printf("proxyProc_fun() SSR_TYPE_DATA\r\n");
            anetWrite(node->fd_real_client,sdsPTR(node->res->body),sdsLength(node->res->body));

            break;
        }

        default:
        {
            printf("serverProc_fun() hacker\r\n");
            break;
        }
    }

    listEmpty(node->res->header_list);

    sdsEmpty(node->buf);
    sdsEmpty(node->res->body);

    httpResponseStatusSet(node->res,HTTP_STATUS_HEAD_VERIFY);

    sdsEmpty(node->res->versions);
    sdsEmpty(node->res->statments);
}
