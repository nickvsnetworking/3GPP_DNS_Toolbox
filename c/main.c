#include <arpa/inet.h>
#include <stdio.h>
#include "dns_resolvers.h"

int main() {
    ResolverContext context0 = {
        .apn = "mms",
        .mnc = "001",
        .mcc = "001",
        .domain_suffix = "3gppnetwork.org.nickvsnetworking.com",
        
        .protocol = "gtp",
        .target = "pgw",
        .interface = "s5",
    };

    ResolverContext context1 = {
        .apn = "internet",
        .mnc = "001",
        .mcc = "001",
        .domain_suffix = "3gppnetwork.org.nickvsnetworking.com",
        
        .protocol = "gtp",
        .target = "pgw",
        .interface = "s5",
    };

    ResolverContext context3 = {
        .apn = "mms",
        .mnc = "001",
        .mcc = "001",
        .domain_suffix = "3gppnetwork.org.nickvsnetworking.com",
        
        .protocol = "gtp",
        .target = "pgw",
        .interface = "s5",
    };

    ResolverContext context2 = {
        .apn = "internet",
        .mnc = "001",
        .mcc = "001",
        .domain_suffix = "3gppnetwork.org.nickvsnetworking.com",
        
        .protocol = "gtp",
        .target = "pgw",
        .interface = "s5",
    };

    ResolverContext context4 = {
        .apn = "internet",
        .mnc = "002",
        .mcc = "002",
        .domain_suffix = "3gppnetwork.org.nickvsnetworking.com",
        
        .protocol = "gtp",
        .target = "pgw",
        .interface = "s5",
    };

    char ipv4[INET_ADDRSTRLEN] = "";

    resolve_naptr(&context0, ipv4, INET_ADDRSTRLEN);
    printf("========================================\n");
    printf("The the final resolved IP is '%s'\n", ipv4);
    resolve_naptr(&context1, ipv4, INET_ADDRSTRLEN);
    printf("========================================\n");
    printf("The the final resolved IP is '%s'\n", ipv4);
    resolve_naptr(&context2, ipv4, INET_ADDRSTRLEN);
    printf("========================================\n");
    printf("The the final resolved IP is '%s'\n", ipv4);
    resolve_naptr(&context3, ipv4, INET_ADDRSTRLEN);
    printf("========================================\n");
    printf("The the final resolved IP is '%s'\n", ipv4);
    resolve_naptr(&context4, ipv4, INET_ADDRSTRLEN);
    printf("========================================\n");
    printf("The the final resolved IP is '%s'\n", ipv4);

    return 0;
}

