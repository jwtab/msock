
#include <unistd.h>
#include <errno.h>

#include <zmalloc.h>
#include <net_main.h>

#include <s5.h>

char S5_STATUS_NAMES[S5_STATUS_Max][64] = {
    "SOCKS5_HANDSHAKE_1",
    "SOCKS5_HANDSHAKE_2",
    "SOCKS5_REQUEST",
    "SOCKS5_RELAY"
};

char S5_AUTH_NAMES[S5_AUTH_Max][64] = {
    "SOCKS5_AUTH_Empty",
    "SOCKS5_AUTH_GSSAPI",
    "SOCKS5_AUTH_Username/Password"
};

s5_fds *s5FDsNew()
{
    s5_fds *s5 = zmalloc(sizeof(s5_fds));
    if(NULL != s5)
    {
        memset(s5,0,sizeof(s5_fds));

        s5->alloc_len = AE_BUF_SIZE;
        s5->buf_len = 0;
        
        s5->upstream_byte = 0;
        s5->downstream_byte = 0;
        
        s5->buf = zmalloc(s5->alloc_len);
    }

    return s5;
}

void s5FDsFree(s5_fds *s5)
{
    if(NULL != s5)
    {
        zfree(s5->buf);
        s5->buf = NULL;

        zfree(s5);
        s5 = NULL;
    }
}

char * s5StatusName(int status)
{
    return S5_STATUS_NAMES[status];
}

char * s5AuthTypeName(int auth_type)
{
    return S5_AUTH_NAMES[auth_type];
}

/*
    +----+----------+----------+
    |VER | NMETHODS | METHODS  |
    +----+----------+----------+
    | 1  |    1     | 1 to 255 |
    +----+----------+----------+

    +----+--------+
    |VER | METHOD |
    +----+--------+
    | 1  |   1    |
    +----+--------+
*/

void s5ClientMethods_Request(s5_fds *s5)
{
    char * data = s5->buf;
    int nMethods = 0;
    int pos = 2;

    if(s5->buf_len >= 2)
    {
        s5->client_version = data[0];
        nMethods = data[1];

        printf("s5ClientMethods_Request socks5_version is %d\r\n",(int)s5->buf[0]);
        printf("s5ClientMethods_Request count is %d\r\n",nMethods);
    }

    while(nMethods)
    {
        printf("s5ClientMethods_Request is %d\r\n",(int)data[pos]);

        pos++;
        nMethods--;
    }
}

void s5ClientMethods_Response(s5_fds *s5)
{
    if(SOCKS_VERSION == (int)s5->client_version)
    {
        /*
        s5->buf[1] = S5_AUTH_USERNAME_PASSWORD;
        s5->auth_type = S5_AUTH_USERNAME_PASSWORD;

        s5->status = S5_STATUS_HANDSHAKE_2;
        */
        s5->buf[1] = S5_AUTH_NONE;
        s5->auth_type = S5_AUTH_NONE;

        s5->status = S5_STATUS_REQUEST;
    }
    else
    {
        s5->buf[1] = 0xFF;
    }

    write(s5->fd_real_client,s5->buf,2);

    printf("s5ClientMethods_Response() auth_type %s\r\n",s5AuthTypeName(s5->auth_type));
}

/*
    +----+------+----------+------+----------+
    |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    +----+------+----------+------+----------+
    | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    +----+------+----------+------+----------+


    +----+--------+
    |VER | STATUS |
    +----+--------+
    | 1  |   1    |
    +----+--------+
*/

void s5ClientAuthUP_Request(s5_fds *s5)
{
    int pos = 0;
    int value_len = 0;
    char *data = s5->buf;

    //auth version.
    s5->auth_version = data[pos];
    pos++;
    printf("s5ClientAuthUP_Request AuthVersion %d\r\n",s5->auth_version);

    //username
    value_len = data[pos];
    pos++;

    memcpy(s5->username,data + pos,value_len);
    printf("s5ClientAuthUP_Request UserName %s\r\n",s5->username);
    pos = pos + value_len;

    //password
    value_len = data[pos];
    pos++;

    memcpy(s5->password,data + pos,value_len);
    printf("s5ClientAuthUP_Request PassWord %s\r\n",s5->password);
    pos = pos + value_len;
}

void s5ClientAuthUP_Response(s5_fds *s5)
{
    //if(SOCKS_AUTH_VERSION == (int)s5->auth_type)
    {
        if(0 == strcmp(S5_USER_NAME,s5->username) && 0 == strcmp(S5_PASSWORD,s5->password))
        {
            s5->buf[1] = SOCKS_AUTH_OK;
            s5->status = S5_STATUS_REQUEST;
        }
        else
        {
            s5->buf[1] = SOCKS_AUTH_ER;
            s5->status = S5_STATUS_RELAY;
        }

        write(s5->fd_real_client,s5->buf,2);
    }
}


/*
    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+

    +----+-----+-------+------+----------+----------+
    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
*/
void s5ClientRequest(const char * data,s5_fds *s5)
{
    int pos = 0;
    short req_type = 0;
    short address_type = 0;
    short data_len = 0;

    //cmd
    req_type = (short)data[pos];
    pos++;
    printf("s5ClientRequest() CMD %d \r\n",req_type);

    if(S5_RequestType_CONNECT != req_type)
    {
        printf("NO DEAL return...");
        return;
    }

    //RSV
    pos++;

    //ATYPE
    address_type = (short)data[pos];
    pos++;
    
    if(S5_AddressType_IPv4 == address_type)
    {
        // socks5://127.0.0.1:1080

        snprintf(s5->real_host,256,"%d.%d.%d.%d",
                    data[pos]&0xff,data[pos+1]&0xff,data[pos+2]&0xff,data[pos+3]&0xff);
        printf("s5ClientRequest() ipv4 %s \r\n",s5->real_host);

        pos = pos + 4;
    }
    else if(S5_AddressType_DOMAINNAME == address_type)
    {
        // socks5h://127.0.0.1:1080

        data_len = (short)data[pos];
        pos++;

        memcpy(s5->real_host,data + pos,data_len);
        printf("s5ClientRequest() hostname %s \r\n",s5->real_host);
        pos = pos + data_len;
    }
    else if(S5_AddressType_IPv6 == address_type)
    {

    }

    //ADR.PORT 网络字节序列.
    memcpy(&s5->real_port,data + pos,2);
    s5->real_port = ntohs(s5->real_port);
    printf("s5ClientRequest() port %d \r\n",s5->real_port);

    pos = pos + 2;
}

void s5ClientRequest_Request(s5_fds *s5)
{
    int pos = 0;
    short req_type = 0;
    short address_type = 0;
    short data_len = 0;
    char *data = s5->buf;

    //version
    printf("s5ClientRequest_Request() version %d \r\n",data[pos]);
    pos++;

    //cmd
    req_type = (short)data[pos];
    pos++;
    printf("s5ClientRequest_Request() CMD %d \r\n",req_type);

    if(S5_RequestType_CONNECT != req_type)
    {
        printf("NO DEAL return...");
        return;
    }

    //RSV
    pos++;

    //ATYPE
    address_type = (short)data[pos];
    pos++;
    
    if(S5_AddressType_IPv4 == address_type)
    {
        // socks5://127.0.0.1:1080

        snprintf(s5->real_host,256,"%d.%d.%d.%d",
                    data[pos]&0xff,data[pos+1]&0xff,data[pos+2]&0xff,data[pos+3]&0xff);
        printf("s5ClientRequest_Request() ipv4 %s \r\n",s5->real_host);

        pos = pos + 4;
    }
    else if(S5_AddressType_DOMAINNAME == address_type)
    {
        // socks5h://127.0.0.1:1080

        data_len = (short)data[pos];
        pos++;

        memcpy(s5->real_host,data + pos,data_len);
        printf("s5ClientRequest_Request() hostname %s \r\n",s5->real_host);
        pos = pos + data_len;
    }
    else if(S5_AddressType_IPv6 == address_type)
    {

    }

    //ADR.PORT 网络字节序列.
    memcpy(&s5->real_port,data + pos,2);
    s5->real_port = ntohs(s5->real_port);
    printf("s5ClientRequest_Request() port %d \r\n",s5->real_port);

    pos = pos + 2;
}

void s5ClientRequest_Response(struct aeEventLoop *eventLoop,aeFileProc *proc,s5_fds *s5)
{
    char err_str[256] = {0};

    s5->fd_real_server = anetTcpNonBlockConnect(err_str,s5->real_host,s5->real_port);
    if(s5->fd_real_server)
    {
        s5->buf[1] = SOCKS_AUTH_OK;
        //memset(s5->buf + 4,0,6);
        
        anetNonBlock(err_str,s5->fd_real_server);

        printf("s5ClientRequest_Response real_client_fd %d\r\n",s5->fd_real_client);
        printf("s5ClientRequest_Response real_server_fd %d\r\n",s5->fd_real_server);

        if(AE_OK != aeCreateFileEvent(eventLoop,s5->fd_real_server,AE_READABLE,proc,s5))
        {
            printf("s5ClientRequest_Response() aeCreateFileEvent(%d) error %d\r\n",s5->fd_real_server,errno);
        }
    }
    else
    {
        s5->buf[1] = SOCKS_AUTH_ER;
        printf("anetTcpNonBlockConnect(%s:%d) error %s \r\n",s5->real_host,s5->real_port,err_str);
    }
    
    s5->status = S5_STATUS_RELAY;
    write(s5->fd_real_client,s5->buf,s5->buf_len);
}

void s5Relay(struct aeEventLoop *eventLoop,int fd,s5_fds *s5)
{
    int fd_read = fd;
    int fd_write = 0;
    int nsended = 0;
    int upstream = 0;

    if(fd_read == s5->fd_real_client)
    {
        upstream = 1;
        fd_write = s5->fd_real_server;
    }
    else
    {
        upstream = 0;
        fd_write = s5->fd_real_client;
    }

    s5->buf_len = anetRead(fd_read,s5->buf,s5->alloc_len);
    if(s5->buf_len > 0)
    {
        printf("s5Relay() read(fd_[%d]) len %d\r\n",fd_read,s5->buf_len);
        nsended = anetWrite(fd_write,s5->buf,s5->buf_len);
        if(s5->buf_len != nsended)
        {
            printf("s5Relay() wirte(fd_[%d]) len %d,errno %d\r\n",fd_write,nsended,errno);
        }
        else
        {
            printf("s5Relay() wirte(fd_[%d]) len %d\r\n",fd_write,s5->buf_len);
        }

        if(upstream > 0)
        {
            s5->upstream_byte = s5->upstream_byte + nsended;
        }
        else
        {
            s5->downstream_byte = s5->downstream_byte + nsended;
        }
    }
    else
    {
        if(0 == s5->buf_len)
        {
            printf("s5Relay() fd_%d closed\r\n",fd);
        }
        else
        {
            printf("s5Relay() fd_%d errno %d\r\n",fd,errno);
        }
        
        printf("s5Relay() session upstream_byte %ld,downstream_byte %ld\r\n",s5->upstream_byte,s5->downstream_byte);

        aeDeleteFileEvent(eventLoop,fd_read,AE_READABLE);
        aeDeleteFileEvent(eventLoop,fd_write,AE_READABLE);

        close(fd_read);
        close(fd_write);

        s5FDsFree(s5);
        s5 = NULL;
    }
}

void s5Process(struct aeEventLoop *eventLoop,int fd,int mask,s5_fds *s5,aeFileProc *proc)
{
    if(mask&AE_READABLE)
    {
        printf("\r\ns5Process() s5_status %s\r\n",s5StatusName(s5->status));

        if(S5_STATUS_HANDSHAKE_1 == s5->status)
        {
            s5->buf_len = read(fd,s5->buf,s5->alloc_len);
            if(s5->buf_len >= 2)
            {
                s5ClientMethods_Request(s5);
                s5ClientMethods_Response(s5);
            }
        }
        else if(S5_STATUS_HANDSHAKE_2 == s5->status)
        {
            s5->buf_len = read(fd,s5->buf,s5->alloc_len);
            if(s5->buf_len >= 2)
            {
                s5ClientAuthUP_Request(s5);
                s5ClientAuthUP_Response(s5);
            }
        }
        else if(S5_STATUS_REQUEST == s5->status)
        {
            s5->buf_len = read(fd,s5->buf,s5->alloc_len);
            if(s5->buf_len)
            {
                s5ClientRequest_Request(s5);
                s5ClientRequest_Response(eventLoop,proc,s5);
            }
        }
        else if(S5_STATUS_RELAY == s5->status)
        {
            s5Relay(eventLoop,fd,s5);
        }
    }
    else if(mask|AE_WRITABLE)
    {

    }
}
