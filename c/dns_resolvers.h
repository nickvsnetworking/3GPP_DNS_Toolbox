#ifndef DNS_RESOLVERS_H
#define DNS_RESOLVERS_H

#include <stdlib.h>
#include <stdbool.h>

typedef struct {
    char target[8];         // "pgw"
    char interface[8];      // "s5"
    char protocol[8];       // "gtp"
    char apn[32];           // "mms"
    char mnc[8];            // "001"
    char mcc[8];            // "100"
    char domain_suffix[64]; // ".3gppnetwork.org.nickvsnetworking.com";
} ResolverContext;

bool resolve_naptr(ResolverContext const * const context, char *buf, size_t buf_sz);

#endif /* DNS_RESOLVERS_H */