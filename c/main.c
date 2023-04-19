#include <arpa/inet.h>
#include <stdio.h>
#include "dns_resolvers.h"

int main() {
    ResolverContext context0 = {
        .apn = "mms",
        .mnc = "001",
        .mcc = "001",
        .domain_suffix = "3gppnetwork.org.nickvsnetworking.com",
        
        .target = "pgw",
        .interface = "s8",
        .protocol = "gtp",
    };

    ResolverContext context2 = {
        .apn = "mms",
        .mnc = "001",
        .mcc = "001",
        .domain_suffix = "3gppnetwork.org.nickvsnetworking.com",
        
        .target = "pgw",
        .interface = "s5",
        .protocol = "gtp",
    };

    char ipv4[INET_ADDRSTRLEN] = "";

    resolve_naptr(&context0, ipv4, INET_ADDRSTRLEN);
    printf("========================================\n");
    printf("The the final resolved IP is '%s'\n", ipv4);

    resolve_naptr(&context0, ipv4, INET_ADDRSTRLEN);
    printf("========================================\n");
    printf("The the final resolved IP is '%s'\n", ipv4);

    return 0;
}

