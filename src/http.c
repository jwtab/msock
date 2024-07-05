
#include <unistd.h>
#include <errno.h>
#include <http.h>

#include <zmalloc.h>
#include <net_inc.h>
#include <net_main.h>

char HTTP_STATUS_NAMES[HTTP_STATUS_Max][64] = {
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

char * httpStatusName(int status)
{
    return HTTP_STATUS_NAMES[status];
}

http_fds *httpFDsNew()
{
    http_fds *http = zmalloc(sizeof(http_fds));
    if(NULL != http)
    {
        memset(http,0,sizeof(http_fds));

        http->alloc_len = HTTP_PROXY_BUF_SIZE;
        http->buf_len = 0;

        http->buf = zmalloc(http->alloc_len);
    }

    return http;
}

void httpFDsFree(http_fds *http)
{
    if(NULL != http)
    {
        if(NULL != http->buf)
        {
            zfree(http->buf);
            http->buf = NULL;
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
    if(0 == strncasecmp(HTTP_PROXY_CONNECT,http->buf,strlen(HTTP_PROXY_CONNECT)))
    {
        _httpProxy_real_destination(http->buf,http->buf_len,http->real_host,&http->real_port);
        printf("httpCONNECT_Request() try_next_destination %s:%d\r\n",http->real_host,http->real_port);
    }
    else
    {
        http->real_port = 0;

        printf("httpCONNECT_Request() %s \r\n",http->buf);
    }
}

/*
    HTTP/1.1 200 Connection Established\r\n\r\n
*/
void httpCONNECT_Response(struct aeEventLoop *eventLoop,aeFileProc *proc,http_fds *http)
{
    char err_str[ANET_ERR_LEN] = {0};

    http->fd_real_server = anetTcpNonBlockConnect(err_str,http->real_host,http->real_port);
    if(http->fd_real_server > 0)
    {
        anetNonBlock(err_str,http->fd_real_server);

        anetRecvTimeout(err_str,http->fd_real_server,SOCKET_RECV_TIMEOUT);
        anetSendTimeout(err_str,http->fd_real_server,SOCKET_SEND_TIMEOUT);

        printf("httpCONNECT_Response() real_client_fd %d\r\n",http->fd_real_client);
        printf("httpCONNECT_Response() real_server_fd %d\r\n",http->fd_real_server);

        if(AE_OK != aeCreateFileEvent(eventLoop,http->fd_real_server,AE_READABLE,proc,http))
        {
            printf("httpCONNECT_Response() aeCreateFileEvent(%d) error %d\r\n",http->fd_real_server,errno);
        }

        strcpy(http->buf,HTTP_PROXY_RET_200);
        http->buf_len = strlen(HTTP_PROXY_RET_200);

        strcat(http->buf,HTTP_PROXY_BODY_END);
        http->buf_len = http->buf_len + strlen(HTTP_PROXY_BODY_END);
    }
    else
    {
        strcpy(http->buf,HTTP_PROXY_RET_502);
        http->buf_len = strlen(HTTP_PROXY_RET_502);

        strcat(http->buf,HTTP_PROXY_BODY_END);
        http->buf_len = http->buf_len + strlen(HTTP_PROXY_BODY_END);

        printf("httpCONNECT_Response(%s:%d) error %s \r\n",http->real_host,http->real_port,err_str);
    }
    
    http->status = HTTP_STATUS_RELAY;
    anetWrite(http->fd_real_client,http->buf,http->buf_len);
}

void httpRelay(struct aeEventLoop *eventLoop,int fd,http_fds *http)
{
    int fd_read = fd;
    int fd_write = 0;
    int nsended = 0;
    int upstream = 0;

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

    http->buf_len = anetRead(fd_read,http->buf,http->alloc_len);
    if(http->buf_len > 0)
    {
        ///printf("httpRelay() anetRead(fd_[%d]) len %d\r\n",fd_read,http->buf_len);
        nsended = anetWrite(fd_write,http->buf,http->buf_len);
        if(http->buf_len != nsended)
        {
            printf("httpRelay() wirte(fd_[%d]) len %d,errno %d\r\n",fd_write,nsended,errno);
        }
        else
        {
            ///printf("httpRelay() wirte(fd_[%d]) len %d\r\n",fd_write,http->buf_len);
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
        if(0 == http->buf_len)
        {
            printf("httpRelay() fd_%d closed\r\n",fd);
        }
        else
        {
            printf("httpRelay() fd_%d errno %d\r\n",fd,errno);
        }

        printf("httpRelay() session upstream_byte %ld,downstream_byte %ld\r\n",http->upstream_byte,http->downstream_byte);

        aeDeleteFileEvent(eventLoop,fd_read,AE_READABLE);
        aeDeleteFileEvent(eventLoop,fd_write,AE_READABLE);

        close(fd_read);
        close(fd_write);

        httpFDsFree(http);
        http = NULL;
    }
}

void httpProcess(struct aeEventLoop *eventLoop,int fd,int mask,http_fds *http,aeFileProc *proc)
{
    if(mask&AE_READABLE)
    {
        ///printf("\r\nhttpProcess() http_status %s\r\n",httpStatusName(http->status));

        if(HTTP_STATUS_CONNECT == http->status)
        {
            http->buf_len = anetRead(fd,http->buf,http->alloc_len);
            if(http->buf_len >= 2)
            {
                httpCONNECT_Request(http);
                if(0 == http->real_port)
                {
                    http->status = HTTP_STATUS_RELAY;
                }
                else
                {
                    httpCONNECT_Response(eventLoop,proc,http);
                }
            }
        }
        else if(HTTP_STATUS_RELAY == http->status)
        {
            httpRelay(eventLoop,fd,http);
        }
    }
}
