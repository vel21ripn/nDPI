#ifdef __KERNEL__

#include <asm/byteorder.h>
#include <linux/kernel.h>

typedef size_t socklen_t;
const char *
inet_ntop (int af, const void *src, char *dst, socklen_t size);
int inet_pton(int af, const char *src, void *dst);
int atoi(const char *);
long int atol(const char *);
void gettimeofday(struct timeval *tv, void *tz);
#endif
