#ifndef DNS_RESOLVERS_H
#define DNS_RESOLVERS_H

#include <stdlib.h>
#include <stdbool.h>


enum { DNS_RESOLVER_MAX_DOMAIN_NAME_STR_LEN = 128 };


typedef struct {
    char target[8];
    char interface[8];
    char protocol[8];
    char apn[32];
    char mnc[8];
    char mcc[8];
    char domain_suffix[64];

    /* Used internally */
    char _domain_name[DNS_RESOLVER_MAX_DOMAIN_NAME_STR_LEN];
} ResolverContext;

/* 
 * Example:
 *   Input:
 *     context->target = "pgw"
 *     context->interface = "s5"
 *     context->protocol = "gtp"
 *     context->apn = "mms"
 *     context->mnc = "001"
 *     context->mcc = "100"
 *     context->domain_suffix = "3gppnetwork.org.nickvsnetworking.com";
 *     buf = ""
 *     buf_sz = 16
 *   Output:
 *     Result = true
 *     buf = "172.20.14.55"
 * 
 * Note:
 *   This will preform a NAPTR lookup, filter out answers that 
 *   don't support our desired service, sort the answers, then
 *   go through each of the answers until we obtain an IPv4 address
 *   that we return.
 *   If we cannot obtain an IP address we return false and do not 
 *   change buf.
 */
bool resolve_naptr(ResolverContext * const context, char *buf, size_t buf_sz);

#endif /* DNS_RESOLVERS_H */