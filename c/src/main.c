#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "dns_resolvers.h"

int main(int argc, char **argv) {

    ResolverContext context = {};
    char ipv4[INET_ADDRSTRLEN] = "";

    if (argc != 8) {
        printf("Not enough arguments for cli runs!\n");
        printf("Expecting something like this:\n");
        printf("\t./main \"<apn>\" \"<mnc>\" \"<mcc>\" \"<domain_suffix>\" \"<target>\" \"<interface>\" \"<protocol>\"\n");
        printf("\t./main \"mms\" \"030\" \"362\" \"3gppnetwork.org\" \"pgw\" \"s5\" \"gtp\"\n\n");


        printf("Running default...\n");
        strncpy(context.apn,           "mms", 32);
        strncpy(context.mnc,           "030", 8);
        strncpy(context.mcc,           "362", 8);
        strncpy(context.domain_suffix, "3gppnetwork.org", 64);
        strncpy(context.target,        "pgw", 8);
        strncpy(context.interface,     "s5", 8);
        strncpy(context.protocol,      "gtp", 8);
    }
    else {

        strncpy(context.apn,           argv[1], 32);
        strncpy(context.mnc,           argv[2], 8);
        strncpy(context.mcc,           argv[3], 8);
        strncpy(context.domain_suffix, argv[4], 64);
        strncpy(context.target,        argv[5], 8);
        strncpy(context.interface,     argv[6], 8);
        strncpy(context.protocol,      argv[7], 8);

        printf("Doing cli run...\n");

    }

    printf("Using the following values:\n");
    printf("apn           : '%s'\n", context.apn);
    printf("mnc           : '%s'\n", context.mnc);
    printf("mcc           : '%s'\n", context.mcc);
    printf("domain_suffix : '%s'\n", context.domain_suffix);
    printf("target        : '%s'\n", context.target);
    printf("interface     : '%s'\n", context.interface);
    printf("protocol      : '%s'\n", context.protocol);


    resolve_naptr(&context, ipv4, INET_ADDRSTRLEN);
    printf("===========================================\n");
    printf("The the final resolved IP is '%s'\n", ipv4);

    return 0;
}

// mms.apn.epc.mnc030.mcc362.3gppnetwork.org
// mms.apn.epc.mnc030.mcc362.3gppnetwork.org