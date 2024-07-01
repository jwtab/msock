
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


#include <s5_udp.h>

static int server_fd = 0;
static int server_run = 0;
pthread_t p_t;

int s5udp_running()
{
    return server_run;
}

int s5udp_start(const char *host,short port)
{
    struct sockaddr_in ser_addr; 

    server_fd = socket(AF_INET,SOCK_DGRAM,0); //AF_INET:IPV4;SOCK_DGRAM:UDP
    if(server_fd < 0)
    {
        printf("create socket fail!\n");
        return -1;
    }
    
    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = inet_addr(host); //IP地址，需要进行网络序转换，INADDR_ANY：本地地址
    ser_addr.sin_port = htons(port);  //端口号，需要网络序转换
    
    int yes = 1;
    /* Make sure connection-intensive things like the redis benchmark
     * will be able to close/open sockets a zillion of times */
    if(-1 == setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)))
    {

    }

    int ret = bind(server_fd, (struct sockaddr*)&ser_addr, sizeof(ser_addr));
    if(ret < 0)
    {
        printf("socket bind fail errno %d\n",errno);
        return -1;
    }

    pthread_create(&p_t,NULL,s5udp_process,NULL);

    return server_fd;
}

void s5udp_stop()
{
    server_run = 0;
}

void s5udp_process(void *arg)
{
    char buf[512] = {0};

    socklen_t len;
    int count;
    
    //clent_addr用于记录发送方的地址信息
    struct sockaddr_in clent_addr;  
    while(server_run)
    {
        memset(buf, 0, 512);
        len = sizeof(clent_addr);

        //recvfrom是拥塞函数，没有数据就一直拥塞.
        count = recvfrom(server_run, buf, 512, 0, (struct sockaddr*)&clent_addr, &len);
        if(count == -1)
        {
            printf("recieve data fail!\n");
            return;
        }

        printf("client:%s\n",buf);

        memset(buf, 0, 512);
        sprintf(buf, "I have recieved %d bytes data!\n", count);  //回复client
        printf("server:%s\n",buf);
        
        //发送信息给client，注意使用了clent_addr结构体指针.
        sendto(server_fd, buf, 512, 0, (struct sockaddr*)&clent_addr, len);  
    }
}
