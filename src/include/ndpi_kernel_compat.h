
#ifndef __NDPI_KERNEL_COMPAT_H__
#define __NDPI_KERNEL_COMPAT_H__

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>

#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/in6.h>
#include <linux/random.h>
#define UINT32_MAX	U32_MAX

/*
 * Linux 7.2 removed strncpy() from the kernel API. nDPI (and xt_ndpi) still
 * uses POSIX strncpy in many places, including bounded copies from packet
 * payloads that are not C strings, so a blanket s/strncpy/strscpy/ is wrong.
 * Restore POSIX semantics for kernel >= 7.2.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 2, 0)
static inline char *ndpi_kstrncpy(char *dest, const char *src, size_t n)
{
       size_t len;

       if (!n)
               return dest;
       len = strnlen(src, n);
       memcpy(dest, src, len);
       if (len < n)
               memset(dest + len, 0, n - len);
       return dest;
}
#define strncpy(dest, src, n) ndpi_kstrncpy(dest, src, n)
#endif

#ifndef MIN
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

typedef long intptr_t;
typedef size_t socklen_t;
const char *
inet_ntop (int af, const void *src, char *dst, socklen_t size);
int inet_pton(int af, const char *src, void *dst);
uint32_t inet_addr(const char *ip);
int atoi(const char *);
long int atol(const char *);
long long int atoll(const char *buf);

void gettimeofday64(struct timespec64 *tv, void *tz);
char *strtok_r(char *str, const char *delim, char **saveptr);
static inline long int strtol(const char *nptr, char **endptr, int base) {
    long int ret;
    if(kstrtol(nptr,base,&ret)) ret = 0;
    return ret;
}

#define be64toh(v) be64_to_cpu(v)
#define le64toh(v) le64_to_cpu(v)
#define le32toh(v) le32_to_cpu(v)
#define le16toh(v) le16_to_cpu(v)
#define be32toh(v) be32_to_cpu(v)
#define be16toh(v) be16_to_cpu(v)
#else
typedef int64_t time64_t;
struct timespec64 {
        time64_t        tv_sec;                 /* seconds */
        long            tv_nsec;                /* nanoseconds */
};
#endif
#endif
