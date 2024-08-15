
#include <unistd.h>

#include <mlog.h>
#include <zmalloc.h>

#include <sys/time.h>

static MLOG * g_mlog = NULL;

char MLOG_LEVEL_STR[MLOG_LEVEL_Max][64] = {
    "[TRACE]",
    "[DEBUG]",
    "[INFO]",
    "[WARN]",
    "[ERROR]",
    "[FATAL]",
};

static void _mlog_write_to_files(MLOG *log)
{
    listNode *node = listFirst(log->logs);
    while(NULL != node)
    {
        sds *tmp = node->value;
        if(NULL != tmp)
        {
            fwrite(sdsPTR(tmp),sdsLength(tmp),1,log->file);
        }
        
        node = node->next;
    }

    listEmpty(log->logs);

    fflush(log->file);
}

static int _mlog_kernel(MLOG *log, MLOG_LEVEL level,char const *fmt,va_list ap)
{
    char buffer[80] = {0};
    struct tm *info;
    struct timeval tm;

    gettimeofday(&tm,NULL);
    if(level < log->mini_level)
    {
        return -1;
    }
    
    info = localtime(&tm.tv_sec);
    snprintf(buffer,80,"%d-%02d-%02d %02d:%02d:%02d.%03d",
        info->tm_year+1900,info->tm_mon,info->tm_mday,
        info->tm_hour,info->tm_min,info->tm_sec,
        tm.tv_usec/1000);

    sds * one = sdsCreateEmpty(2048);
    int size = 0;

    sdsCatprintf(one,"%s %s ",buffer,MLOG_LEVEL_STR[level]);
    sdsCatvprintf(one,fmt,ap);

    sdsCat(one,"\r\n");

    //准备写入到列表中.
    pthread_mutex_lock(&log->mutex);
    
    listAddNodeTail(log->logs,one);
    size = listLength(log->logs);
    
    pthread_mutex_unlock(&log->mutex);
    
    return size;
}

void *_mlog_writing_thread(void *mlog_ptr)
{
    MLOG * log = (MLOG*)mlog_ptr;

    while(log->running)
    {
        pthread_mutex_lock(&log->mutex);

        int count = listLength(log->logs);
        if(count > 0)
        {
            _mlog_write_to_files(log);
        }

        pthread_mutex_unlock(&log->mutex);

        sleep(MLOG_FLUSH_SECONDS);
    }

    return NULL;
}

void _mlog_free_one_line(void *ptr)
{
    sds *line = (sds*)ptr;
    sdsRelease(line);
    line = NULL;
}

MLOG * mlogNew(const char *log_path)
{
    if(NULL == g_mlog)
    {
        g_mlog = (MLOG*)zmalloc(sizeof(MLOG));
        if(NULL != g_mlog)
        {
            g_mlog->ref_count = 0;
            strcpy(g_mlog->log_path,log_path);
            
            g_mlog->file = fopen(g_mlog->log_path,"a+");
            if(NULL != g_mlog->file)
            {
                g_mlog->ref_count = 1;

                g_mlog->logs = listCreate();
                if(NULL != g_mlog->logs)
                {
                    listSetFreeMethod(g_mlog->logs,_mlog_free_one_line);
                }

                g_mlog->mini_level = MLOG_LEVEL_INFO;

                g_mlog->running = true;
                pthread_mutex_init(&g_mlog->mutex,NULL);

                pthread_create(&g_mlog->thread_w,NULL,_mlog_writing_thread,g_mlog);
            }
        }
    }
    else
    {
        return g_mlog;
    }

    return g_mlog;
}

void mlogRelease(MLOG *log)
{
    if(NULL != log)
    {
        log->ref_count--;

        if(log->ref_count <= 0)
        {
            g_mlog->running = false;

            pthread_join(g_mlog->thread_w,NULL);

            pthread_mutex_destroy(&g_mlog->mutex);

            _mlog_write_to_files(log);
            listRelease(log->logs);

            fclose(log->file);
            log->file = NULL;

            zfree(log);
            log = NULL;
        }
    }
}

MLOG * mlogGet()
{
    if(NULL != g_mlog)
    {
        g_mlog->ref_count++;
    }
    
    return g_mlog;
}

void mlogUUID(char *uuid)
{
    char uuidgen_buf[1024] = {0};

    FILE * fp = popen("uuidgen -t","r");
    if(NULL != fp)
    {
        if(NULL != fgets(uuidgen_buf, sizeof(uuidgen_buf), fp))
        {
            strncpy(uuid,uuidgen_buf,36);
        }

        pclose(fp);
        fp = NULL;
    }
}

long mlogTick_ms()
{
    long ret = 0;
    struct timeval tm;

    gettimeofday(&tm,NULL);

    ret = 1000*tm.tv_sec + tm.tv_usec;

    return ret;
}

void mlogTick_gmt(char *gmt_str,int size)
{
    time_t now = time(NULL);
    struct tm *gmt = gmtime(&now);

    strftime(gmt_str,size,"%a,%d %b %Y %H:%M:%S GMT",gmt);
}

void mlogMinLevelSet(MLOG *log, MLOG_LEVEL level)
{
    log->mini_level = level;
}

MLOG_LEVEL mlogMinLevelGet(MLOG *log)
{
    return log->mini_level;
}

int mlogBase(MLOG *log, MLOG_LEVEL level,char const *fmt, ...)
{
    int size = 0;
    va_list ap;

    if(NULL == log)
    {
        return -1;
    }

    va_start(ap, fmt);
    size = _mlog_kernel(log,level,fmt,ap);
    va_end(ap);

    return size;
}

int mlogTrace(MLOG *log, char const *fmt, ...)
{
    int size = 0;
    va_list ap;

    va_start(ap, fmt);
    size = _mlog_kernel(log,MLOG_LEVEL_TRACE,fmt,ap);
    va_end(ap);

    return size;
}

int mlogDebug(MLOG *log, char const *fmt, ...)
{
    int size = 0;
    va_list ap;

    va_start(ap, fmt);
    size = _mlog_kernel(log,MLOG_LEVEL_DEBUG,fmt,ap);
    va_end(ap);

    return size;
}

int mlogInfo(MLOG *log, char const *fmt, ...)
{
    int size = 0;
    va_list ap;

    va_start(ap, fmt);
    size = _mlog_kernel(log,MLOG_LEVEL_INFO,fmt,ap);
    va_end(ap);

    return size;
}

int mlogWarn(MLOG *log, char const *fmt, ...)
{
    int size = 0;
    va_list ap;

    va_start(ap, fmt);
    size = _mlog_kernel(log,MLOG_LEVEL_WARN,fmt,ap);
    va_end(ap);

    return size;
}

int mlogError(MLOG *log, char const *fmt, ...)
{
    int size = 0;
    va_list ap;

    va_start(ap, fmt);
    size = _mlog_kernel(log,MLOG_LEVEL_ERROR,fmt,ap);
    va_end(ap);

    return size;
}

int mlogFatal(MLOG *log, char const *fmt, ...)
{
    int size = 0;
    va_list ap;

    va_start(ap, fmt);
    size = _mlog_kernel(log,MLOG_LEVEL_FATAL,fmt,ap);
    va_end(ap);

    return size;
}
