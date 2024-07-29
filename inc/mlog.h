
#ifndef __MLOG_H__
#define __MLOG_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <sds.h>

typedef struct _mlog
{
    FILE * file;

    char log_path[1024];

    int ref_count;
}MLOG;

MLOG * mlogNew(const char *log_path);
void mlogRelease(MLOG *log);
MLOG * mlogGet();

void mlogUUID(char *uuid);

long mlogTick_ms();
void mlogTick_gmt(char *gmt_str,int size);

#endif //__MLOG_H__
