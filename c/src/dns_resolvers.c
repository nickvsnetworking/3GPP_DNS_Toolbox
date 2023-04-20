#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <resolv.h>
#include "naptr.h"
#include "regex_extensions.h"
#include "dns_resolvers.h"


enum { MAX_ANSWER_BYTES = 1024 };


static bool build_domain_name(ResolverContext * const context);
static naptr_resource_record * filter_nrrs(ResolverContext const * const context, naptr_resource_record *nrrs);
static bool should_remove(ResolverContext const * const context, naptr_resource_record *nrr);
static naptr_resource_record * get_best_nrr(naptr_resource_record *nrrs);
static void transform_domain_name(naptr_resource_record *nrr, char * dname);
static int type_ip_query(char lookup_type, char * dname, char * buf, size_t buf_sz);


// todo remove
static void print_nrr(naptr_resource_record *nrr) {
    printf("nrr->preference    : %i\n",   nrr->preference);
    printf("nrr->order         : %i\n",   nrr->order);
    printf("nrr->flag          : '%c'\n", nrr->flag);
    printf("nrr->service       : '%s'\n", nrr->service);
    printf("nrr->regex_pattern : '%s'\n", nrr->regex_pattern);
    printf("nrr->regex_replace : '%s'\n", nrr->regex_replace);
    printf("nrr->replacement   : '%s'\n", nrr->replacement);
}

// todo remove
static void print_nrrs(naptr_resource_record *nrrs) {
    int i = 0;

    while (NULL != nrrs) {
        printf("\nResult %i:\n", i);
        print_nrr(nrrs);

        ++i;
        nrrs = nrrs->next;
    }
}

/* Takes in a context and returns an ip? */
bool resolve_naptr(ResolverContext * const context, char *buf, size_t buf_sz) {
    bool resolved = false;
    naptr_resource_record *nrr = NULL;
    naptr_resource_record *nrr_list = NULL;

    if ((NULL == context) || (NULL == buf)) return false;

    /* Build domain name */
    build_domain_name(context);

    /* Get all NRRs */
    nrr_list = naptr_query(context->_domain_name);
    if (NULL == nrr_list) return false;

    /* Remove all the NRRs that don't provide the desired service */
    printf("before filter_nrrs` %i\n", naptr_resource_record_list_count(nrr_list));
    nrr_list = filter_nrrs(context, nrr_list);

    /* Sort the NRRs so that we can resolve them in order of priority */
    printf("before naptr_list_head %i\n", naptr_resource_record_list_count(nrr_list));
    nrr_list = naptr_list_head(nrr_list);
    printf("before sort count %i\n", naptr_resource_record_list_count(nrr_list));
    nrr = naptr_sort(&nrr_list);
    printf("after sort count %i\n", naptr_resource_record_list_count(nrr));


    while (nrr != NULL) {
        /* Update domain name */
        transform_domain_name(nrr, context->_domain_name);

        printf("Doing '%c' lookup for '%s'\n", nrr->flag, context->_domain_name);
        /* Go through the NRRs until we get an IP */
        int num_ips = type_ip_query(nrr->flag, context->_domain_name, buf, buf_sz);

        if (0 < num_ips) break;

        nrr = nrr->next;
    }

    naptr_free_resource_record_list(nrr_list);

    return resolved;
}

static bool build_domain_name(ResolverContext * const context) {
    int chars_written = 0;
    bool build_success = false;

    if (NULL == context) return false;

    /* If we don't have an APN specified we use the target */
    if (0 == strlen(context->apn)) {
        chars_written = snprintf(
            context->_domain_name,
            DNS_RESOLVER_MAX_DOMAIN_NAME_STR_LEN,
            "%s.epc.mnc%s.mcc%s.%s", 
            context->target,
            context->mnc,
            context->mcc,
            context->domain_suffix
        );
    } else {
        chars_written = snprintf(
            context->_domain_name,
            DNS_RESOLVER_MAX_DOMAIN_NAME_STR_LEN,
            "%s.apn.epc.mnc%s.mcc%s.%s", 
            context->apn,
            context->mnc,
            context->mcc,
            context->domain_suffix
        );
    }

    if (chars_written < DNS_RESOLVER_MAX_DOMAIN_NAME_STR_LEN) {
        build_success = true;
    }

    return build_success;
}


/* 
squeezing into open5gs is still needed
SRV will need to be sorted and stuff

 */

/**
 * Cases:
 *   1) If filter results in empty list NULL will be returned
 *   2) If filter results in non-empty list then the last node
 *      is returned.
 */
static naptr_resource_record * filter_nrrs(ResolverContext const * const context, naptr_resource_record *nrr) {
    naptr_resource_record *prev = NULL;
    naptr_resource_record *next = NULL;

    if ((NULL == context) || (NULL == nrr)) return NULL;

    nrr = naptr_list_head(nrr);

    while (NULL != nrr) {
        next = nrr->next;

        if (should_remove(context, nrr)) {
            nrr = naptr_remove_resource_record(nrr);
        }

        prev = nrr;
        nrr = next;
    }

    return prev;
}



static bool has_appropriate_services(ResolverContext const * const context, naptr_resource_record *nrr) {
    bool has_appropriate_services = false;
    enum { DESIRED_STR_LEN = 128 };
    char desired_target_string[DESIRED_STR_LEN] = "";
    char desired_service_string[DESIRED_STR_LEN] = "";

    if ((NULL == context) || (NULL == nrr)) return NULL;

    /* Build our desired services strings */
    snprintf(desired_target_string, DESIRED_STR_LEN, "x-3gpp-%s", context->target);
    snprintf(desired_service_string, DESIRED_STR_LEN, "x-%s-%s", context->interface, context->protocol);

    printf("desired_service_string '%s'\n", desired_service_string);
    printf("desired_target_string '%s'\n", desired_target_string);

    if ((NULL != strstr(nrr->service, desired_service_string)) &&
        (NULL != strstr(nrr->service, desired_target_string))) {
        has_appropriate_services = true;
    }

    return has_appropriate_services;
}

/* We want this  */
static bool has_replace_has_no_regex(ResolverContext const * const context, naptr_resource_record *nrr) {
    bool has_replace_has_no_regex = false;

    if ((NULL == context) || (NULL == nrr)) return NULL;


    printf("replacement field is '%s'\n", nrr->replacement);
    printf("pattern field is '%s'\n", nrr->regex_pattern);

    /* Has replacement field */
    if ((0 < strlen(nrr->replacement)) &&
        (0 != strcmp(nrr->replacement, "."))) {
            printf("This one has a replacement field\n");

        /* Has no regex fields */
        if ((0 == strlen(nrr->regex_pattern)) &&
            (0 == strlen(nrr->regex_pattern))) {
            has_replace_has_no_regex = true;     
            printf("Also has no regex field!\n");
        }
    }

    return has_replace_has_no_regex;
}


static bool has_regex_match(ResolverContext const * const context, naptr_resource_record *nrr) {
    bool has_regex_match = false;

    if ((NULL == context) || (NULL == nrr)) return NULL;



    if (false == reg_match(nrr->regex_pattern, context->_domain_name)) {
        has_regex_match = true;
        printf("has a regex match!\n");
    }
    else 
    {
        printf("regex failed to match!\n");
    }

    return has_regex_match;
}

/*
 * RFC 2915 (4. The Basic NAPTR Algorithm)
 * 
 * NAPTR records for this key are retrieved, those with unknown Flags or
 * inappropriate Services are discarded and the remaining records are
 * sorted by their Order field.  Within each value of Order, the records
 * are further sorted by the Preferences field.
 * 
 * The records are examined in sorted order until a matching record is
 * found.  A record is considered a match iff:
 *   - it has a Replacement field value instead of a Regexp field value.
 *   - or the Regexp field matches the string held by the client.
 * 
 * TLDR:
 *   We only keep if:
 *     - Known flag
 *     - Appropriate services
 *     - It has a replacement field AND no regex field
 *     - It has a regex field that does not match the string
 * 
 */
static bool should_remove(ResolverContext const * const context, naptr_resource_record *nrr) {
    bool should_remove = false;

    if ((NULL == context) || (NULL == nrr)) return true;

    printf("Testing if we should reject:\n");
    printf("Target '%s'\n", context->target);
    printf("APN '%s'\n", context->apn);
    printf("interface '%s'\n", context->interface);
    printf("domain_suffix '%s'\n", context->domain_suffix);
    printf("mcc '%s'\n", context->mcc);
    printf("mnc '%s'\n", context->mnc);
    printf("protocol '%s'\n", context->protocol);
    print_nrr(nrr);


    if (false == has_appropriate_services(context, nrr)) {
        /* Excluding this peer due to not handling desired services */
        printf("Excluding this peer due to not handling desired services\n");
        should_remove = true;
    }
    
    else if (true == has_replace_has_no_regex(context, nrr)) {
        /* It has a replacement field AND no regex field */
        /* OR it has a regex field that matches the domain name */
        should_remove = false;
    } else if (true == has_regex_match(context, nrr)) {
        should_remove = false;
    } else {
        /* This peer provides requested target node & service */
        printf("Excluding this peer as it has a replacement field AND no regex field\n");
        should_remove = true;
    }
    printf("should_remove: %i\n", should_remove);
    printf("\n\n\n");


    return should_remove;
}

/*
 * Example (regex replace):
 *   Input:
 *     nrr->regex_pattern = "([a-z0-9]+)(..*)"
 *     nrr->regex_replace = "\\1.apn.epc.mnc999.mcc999.3gppnetwork.org"
 *     nrr->replacement = "."
 *     dname = "mms.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com"
 *   Output:
 *     dname = "mms.apn.epc.mnc999.mcc999.3gppnetwork.org"
 * 
 * Example (replace):
 *   Input:
 *     nrr->regex_pattern = ""
 *     nrr->regex_replace = ""
 *     nrr->replacement = "www.google.com"
 *     dname = "mms.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com"
 *   Output:
 *     dname = "www.google.com"
 * 
 * Notes:
 *   If any of the pointers are NULL then the function will immediately return
 *   without making any changes.
 *   We assume that all strings (char*) are correctly terminated.
 *   Assuming that dname is of size DNS_RESOLVER_MAX_DOMAIN_NAME_STR_LEN.
 */
static void transform_domain_name(naptr_resource_record *nrr, char * dname) {
    if ((NULL == nrr) || (NULL == dname)) return;

    /* If a Regex Replaces is set on the DNS entry then evaluate it and apply it */
    if ((0 < strlen(nrr->regex_pattern)) &&
        (0 < strlen(nrr->regex_replace))) {
        int reg_replace_res;
        char temp[DNS_RESOLVER_MAX_DOMAIN_NAME_STR_LEN] = "";

        reg_replace_res = reg_replace(nrr->regex_pattern, nrr->regex_replace, dname, temp, DNS_RESOLVER_MAX_DOMAIN_NAME_STR_LEN);

        if (1 == reg_replace_res) {
            strncpy(dname, temp, DNS_RESOLVER_MAX_DOMAIN_NAME_STR_LEN - 1);
        } else {
            printf("Failed to preform regex replace!\n");
        }
    } else if (0 != strcmp(nrr->replacement, ".")) {
        strncpy(dname, nrr->replacement, DNS_RESOLVER_MAX_DOMAIN_NAME_STR_LEN - 1);
    } else {
        /* No changes made to domain name */
    }
}

/* TODO this should be changed and moved to a more appropriate area. 
 * It should return a query result and not a single IP.
 * It should also be renamed to a_query or srv_query */
static int type_ip_query(char lookup_type, char * dname, char * buf, size_t buf_sz) {
    int ip_count = 0;
    int resolv_lookup_type; 
    unsigned char answer[MAX_ANSWER_BYTES];
    ns_rr record;
    ns_msg handle;

    if ((NULL == dname) || (NULL == buf)) return 0;

    if (('a' == lookup_type) || (0 == lookup_type)) {
        resolv_lookup_type = T_A; 
        // return 0; // temp, remove me after building SRV stuff
    } else if ('s' == lookup_type) {
        resolv_lookup_type = T_SRV; 
    } else {
        printf("Unsupported lookup type");
        return 0;
    }

    int bytes_received, i, result;

    // Send DNS query for A record type
    bytes_received = res_query(dname, C_IN, resolv_lookup_type, answer, MAX_ANSWER_BYTES);
    printf("[%c-lookup] Query for '%s' resulted in %i bytes received\n", lookup_type, dname, bytes_received);
    if (bytes_received < 0) {
        return 0;
    }

    // Initialize message handle
    result = ns_initparse(answer, bytes_received, &handle);
    if (result < 0) {
        perror("ns_initparse");
        return 0;
    }

    // Extract and print A records
    for (i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
        result = ns_parserr(&handle, ns_s_an, i, &record);
        if (result < 0) {
            perror("ns_parserr");
            return 0;
        }

        if (ns_rr_type(record) == T_A) {
            inet_ntop(AF_INET, ns_rr_rdata(record), buf, buf_sz);
            ++ip_count;
        } else if (ns_rr_type(record) == T_SRV) {
            /* TODO */
            /* This will have weights and stuff then balance some stuff */
            printf("SRV lookup is currently not implemented!\n");
        }
    }

    return ip_count;
}
