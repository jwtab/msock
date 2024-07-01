
#include <unistd.h>
#include <errno.h>

#include <zmalloc.h>
#include <net_main.h>

#include <s5.h>
#include <s5_udp.h>

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

        s5->buf_len = AE_BUF_SIZE;
        s5->buf = zmalloc(s5->buf_len);
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
void s5ClientMethods(const char * data)
{
    int pos = 1;
    int nMethods = (int)data[0];

    printf("s5ClientMethods count is %d\r\n",nMethods);
    
    while(nMethods)
    {
        printf("s5ClientMethods is %d\r\n",(int)data[pos]);

        pos++;
        nMethods--;
    }
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
void s5ClientUNamePwd(const char * data,s5_fds *s5)
{
    int pos = 0;
    int value_len = 0;

    //username
    value_len = data[pos];
    pos++;

    memcpy(s5->username,data + pos,value_len);
    printf("s5Client UserName %s\r\n",s5->username);
    pos = pos + value_len;

    //password
    value_len = data[pos];
    pos++;

    memcpy(s5->password,data + pos,value_len);
    printf("s5Client PassWord %s\r\n",s5->password);
    pos = pos + value_len;
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
        snprintf(s5->real_host,256,"%d.%d.%d.%d",
                    data[pos]&0xff,data[pos+1]&0xff,data[pos+2]&0xff,data[pos+3]&0xff);
        printf("s5ClientRequest() ipv4 %s \r\n",s5->real_host);

        pos = pos + 4;
    }
    else if(S5_AddressType_DOMAINNAME == address_type)
    {
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

void s5Process(struct aeEventLoop *eventLoop,int fd,int mask,s5_fds *s5,aeFileProc *proc)
{
    ssize_t len = 0;
    ssize_t write_len = 0;
    char err_str[256] = {0};

    if(mask&AE_READABLE)
    {
        if(S5_STATUS_HANDSHAKE_1 == s5->status)
        {
            len = read(fd,s5->buf,s5->buf_len);
            if(len)
            {
                printf("Client Socks version is %d\r\n",(int)s5->buf[0]);
                if(SOCKS_VERSION == (int)s5->buf[0])
                {
                    s5ClientMethods(s5->buf + 1);

                    //写入数据.
                    s5->buf[0] = SOCKS_VERSION;
                    s5->buf[1] = S5_AUTH_USERNAME_PASSWORD;
                    //s5->buf[1] = S5_AUTH_NONE;
                    write(fd,s5->buf,2);

                    s5->status = S5_STATUS_HANDSHAKE_2;
                    s5->auth = S5_AUTH_USERNAME_PASSWORD;
                }
            }
        }
        else if(S5_STATUS_HANDSHAKE_2 == s5->status)
        {
            len = read(fd,s5->buf,s5->buf_len);
            if(len)
            {
                printf("Client Socks auth_version is %d\r\n",(int)s5->buf[0]);
                if(SOCKS_AUTH_VERSION == (int)s5->buf[0])
                {
                    s5ClientUNamePwd(s5->buf + 1,s5);

                    //写入数据.
                    s5->buf[0] = SOCKS_AUTH_VERSION;
                    s5->buf[1] = SOCKS_AUTH_OK;
                    write(fd,s5->buf,2);

                    s5->status = S5_STATUS_REQUEST;
                }
            }
        }
        else if(S5_STATUS_REQUEST == s5->status)
        {
            len = read(fd,s5->buf,s5->buf_len);
            if(len)
            {
                printf("Client Socks version is %d\r\n",(int)s5->buf[0]);
                if(SOCKS_VERSION == (int)s5->buf[0])
                {
                    s5ClientRequest(s5->buf + 1,s5);
                    s5->fd_real_server = anetTcpNonBlockConnect(err_str,s5->real_host,s5->real_port);
                    if(s5->fd_real_server)
                    {
                        s5->status = S5_STATUS_RELAY;

                        s5->buf[1] = 0x00;
                        //memset(s5->buf + 4,0,6);
                        if(s5udp_running() <= 0)
                        {
                            s5udp_start("127.0.0.1",1081);
                        }

                        int ip = inet_addr("127.0.0.1");
                        short port = htons(1081);
                        memcpy(s5->buf + 4,&ip,4);
                        memcpy(s5->buf + 6,&port,2);

                        write(fd,s5->buf,len);
                        
                        anetNonBlock(err_str,s5->fd_real_server);

                        printf("real_client_fd %d\r\n",s5->fd_real_client);
                        printf("real_server_fd %d\r\n",s5->fd_real_server);

                        aeCreateFileEvent(eventLoop,s5->fd_real_server,AE_READABLE,proc,s5);
                    }
                    else
                    {
                        printf("anetTcpNonBlockConnect(%s:%d) error %s \r\n",s5->real_host,s5->real_port,err_str);
                    }
                }
            }
        }
        else if(S5_STATUS_RELAY == s5->status)
        {
            int fd_read = fd;
            int fd_write = 0;

            if(fd_read == s5->fd_real_client)
            {
                fd_write = s5->fd_real_server;
            }
            else
            {
                fd_write = s5->fd_real_client;
            }

            len = read(fd_read,s5->buf,s5->buf_len);
            if(len > 0)
            {
                write_len = write(fd_write,s5->buf,len);
                printf("S5_STATUS_RELAY fd_[%d] --> fd_[%d] len %ld\r\n",fd_read,fd_write,write_len);
            }
            else
            {
                printf("S5_STATUS_RELAY fd_%d errno %d\r\n",fd,errno);
                aeDeleteFileEvent(eventLoop,fd_read,AE_READABLE);
                aeDeleteFileEvent(eventLoop,fd_write,AE_READABLE);

                close(fd_read);
                close(fd_write);

                s5FDsFree(s5);
                s5 = NULL;
            }
        }
    }
    else if(mask|AE_WRITABLE)
    {

    }
}
