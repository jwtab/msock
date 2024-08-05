
#ifndef __MLOG_H__
#define __MLOG_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <sds.h>
#include <adlist.h>

#define MLOG_FLUSH_LINE_COUNT 10

typedef enum _mlog_level
{
    MLOG_LEVEL_TRACE = 0x00,
    MLOG_LEVEL_DEBUG,
    MLOG_LEVEL_INFO,
    MLOG_LEVEL_WARN,
    MLOG_LEVEL_ERROR,
    MLOG_LEVEL_FATAL,
    MLOG_LEVEL_Max
}MLOG_LEVEL;

typedef struct _mlog
{
    FILE * file;
    list *logs;

    char log_path[1024];
    int ref_count;

    MLOG_LEVEL mini_level;
}MLOG;

MLOG * mlogNew(const char *log_path);
void mlogRelease(MLOG *log);
MLOG * mlogGet();

void mlogUUID(char *uuid);

long mlogTick_ms();
void mlogTick_gmt(char *gmt_str,int size);

void mlogMinLevelSet(MLOG *log, MLOG_LEVEL level);
MLOG_LEVEL mlogMinLevelGet(MLOG *log);

int mlogBase(MLOG *log, MLOG_LEVEL level,char const *fmt, ...);

int mlogTrace(MLOG *log, char const *fmt, ...);
int mlogDebug(MLOG *log, char const *fmt, ...);
int mlogInfo(MLOG *log, char const *fmt, ...);
int mlogWarn(MLOG *log, char const *fmt, ...);
int mlogError(MLOG *log, char const *fmt, ...);
int mlogFatal(MLOG *log, char const *fmt, ...);

#endif //__MLOG_H__
