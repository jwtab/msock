#ifndef __NET_INC_H__
#define __NET_INC_H__

#include <sys/time.h>
#include <stdbool.h>

#define AE_OK 0
#define AE_ERR -1

#define AE_NONE 0       /* No events registered. */
#define AE_READABLE 1   /* Fire when descriptor is readable. */
#define AE_WRITABLE 2   /* Fire when descriptor is writable. */
#define AE_BARRIER 4    /* With WRITABLE, never fire the event if the
                           READABLE event already fired in the same event
                           loop iteration. Useful when you want to persist
                           things to disk before sending replies, and want
                           to do that in a group fashion. */

#define AE_FILE_EVENTS (1<<0)
#define AE_TIME_EVENTS (1<<1)
#define AE_ALL_EVENTS (AE_FILE_EVENTS|AE_TIME_EVENTS)
#define AE_DONT_WAIT (1<<2)


//ms为单位.
#define SOCKET_RECV_TIMEOUT 1500
#define SOCKET_SEND_TIMEOUT 1500

/*
    定义是否走ssr代理.
*/
typedef enum _PROXY_TYPE
{
    PROXY_TYPE_LOCAL = 0x01,
    PROXY_TYPE_SSR,
    PROXY_TYPE_AUTO,
    PROXY_TYPE_Max
}PROXY_TYPE;

#define SSR_HOST "msock.duckdns.org"
#define SSR_PORT 443
#define SSR_HEAD_HOST "msock.duckdns.org"

struct aeEventLoop;

/* Types and data structures */
typedef void aeFileProc(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask);

/* File event structure */
typedef struct aeFileEvent 
{
    int mask; /* one of AE_(READABLE|WRITABLE|BARRIER) */
    aeFileProc *rfileProc;
    aeFileProc *wfileProc;
    void *clientData;
} aeFileEvent;

/* A fired event */
typedef struct aeFiredEvent {
    int fd;
    int mask;
} aeFiredEvent;

/* State of an event based program */
typedef struct aeEventLoop 
{
    int maxfd;   /* highest file descriptor currently registered */
    int setsize; /* max number of file descriptors tracked */
    aeFileEvent *events; /* Registered events */
    aeFiredEvent *fired; /* Fired events */
    int stop;
    void *apidata; /* This is used for polling API specific data */
    int flags;

    void * ref_log_ptr;
} aeEventLoop;


int aeApiCreate(aeEventLoop *eventLoop);
int aeApiResize(aeEventLoop *eventLoop, int setsize);
void aeApiFree(aeEventLoop *eventLoop);
int aeApiAddEvent(aeEventLoop *eventLoop, int fd, int mask);
void aeApiDelEvent(aeEventLoop *eventLoop, int fd, int delmask);
int aeApiPoll(aeEventLoop *eventLoop, struct timeval *tvp);
char *aeApiName(void);

#endif //__NET_INC_H__
