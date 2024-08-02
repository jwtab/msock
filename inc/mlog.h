
#ifndef __MLOG_H__
#define __MLOG_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <sds.h>
#include <adlist.h>

#define MLOG_FLUSH_LINE_COUNT 10

typedef struct _mlog
{
    FILE * file;
    list *logs;

    char log_path[1024];
    int ref_count;
}MLOG;

MLOG * mlogNew(const char *log_path);
void mlogRelease(MLOG *log);
MLOG * mlogGet();

void mlogUUID(char *uuid);

long mlogTick_ms();
void mlogTick_gmt(char *gmt_str,int size);

int mlogPrintf(MLOG *log, char const *fmt, ...);

#endif //__MLOG_H__
