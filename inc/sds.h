
#ifndef __SDS_H__
#define __SDS_H__

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct sds
{
    // used.
    uint32_t len;

    //including the data and null terminator. MINI_alloc = len + 1
    uint32_t alloc;

    // real data.
    char * data;
}sds;

// Public functions.
sds *sdsCreateEmpty(uint32_t initsize);
sds *sdsCreateL(const void *init, uint32_t initlen);
sds *sdsCreate(const char *init);

sds *sdsDup(const sds *s);
void sdsRelease(sds *s);
void sdsEmpty(sds *s);

uint32_t sdsLength(const sds *s);
uint32_t sdsAvail(const sds *s);

const char * sdsString(const sds *s,uint32_t pos);
char * sdsPTR(const sds *s);

sds *sdsCatsds(sds *s, const sds t);

sds *sdsCatlen(sds *s, const void *t, size_t len);
sds *sdsCat(sds *s, const char *t);

sds *sdsCpylen(sds *s, const char *t, size_t len);
sds *sdsCpy(sds *s, const char *t);

sds *sdsCatvprintf(sds *s, const char *fmt, va_list ap);
sds *sdsCatprintf(sds *s, char const *fmt, ...);

char sdsChar(sds *s,uint32_t index);

#endif
