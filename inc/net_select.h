
#ifndef __NET_SELECT_H__
#define __NET_SELECT_H__

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <net_inc.h>

/*
#ifdef __APPLE__

typedef struct aeApiState 
{
    fd_set rfds, wfds;
    fd_set _rfds, _wfds;
} aeApiState;

int aeApiCreate(aeEventLoop *eventLoop);
int aeApiResize(aeEventLoop *eventLoop, int setsize);
void aeApiFree(aeEventLoop *eventLoop);
int aeApiAddEvent(aeEventLoop *eventLoop, int fd, int mask);
void aeApiDelEvent(aeEventLoop *eventLoop, int fd, int delmask);
int aeApiPoll(aeEventLoop *eventLoop, struct timeval *tvp);
char *aeApiName(void);

#endif //__APPLE__
*/

#endif //__NET_SELECT_H__
