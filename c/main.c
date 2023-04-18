#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <regex.h>
#include "naptr.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <resolv.h>
#include <ctype.h>


typedef struct {
    char target[8];         // "pgw"
    char interface[8];      // "s5"
    char protocol[8];       // "gtp"
    char apn[32];           // "mms"
    char mnc[8];            // "001"
    char mcc[8];            // "100"
    char domain_suffix[64]; // ".3gppnetwork.org.nickvsnetworking.com";
} ResolverContext;

static bool build_domain_name(ResolverContext const * const context, char * const buf, size_t buf_sz);
static naptr_resource_record * filter_nrrs(ResolverContext const * const context, naptr_resource_record *nrrs);
static bool should_remove(ResolverContext const * const context, naptr_resource_record *nrr);
static naptr_resource_record * get_best_nrr(naptr_resource_record *nrrs);
static void transform_domain_name(naptr_resource_record *nrr, char * dname, size_t max_dname_sz);
static int record_lookup(char lookup_type, char * dname, char * buf, size_t buf_sz);

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

#define SR_RE_MAX_MATCH 6


















/*! \brief Replace in replacement tokens \\d with substrings of string pointed by
 * pmatch.
 */
int replace(regmatch_t* pmatch, char* string, char* replacement, char* result)
{
	int len, i, j, digit, size;

    int rlen = 200;

	len = strlen(replacement);
	j = 0;

	for (i = 0; i < len; i++) {
		if (replacement[i] == '\\') {
            printf("passed first challange\n");
			if (i < len - 1) {
				if (isdigit((unsigned char)replacement[i+1])) {
					digit = replacement[i+1] - '0';
					if (pmatch[digit].rm_so != -1) {
						size = pmatch[digit].rm_eo - pmatch[digit].rm_so;
						if (j + size < rlen) {
							memcpy(&(result[j]), string+pmatch[digit].rm_so, size);
							j = j + size;
						} else {
							return -1;
						}
					} else {
						return -2;
					}
					i = i + 1;
					continue;
				} else {
					i = i + 1;
				}
			} else {
				return -3;
			}
		}

		if (j + 1 < rlen) {
			result[j] = replacement[i];
			j = j + 1;
		} else {
			return -4;
		}
	}
	// strlen(result) = j;
	return 1;
}

/*! \brief Match pattern against string and store result in pmatch */
static int reg_match(char *pattern, char *string, regmatch_t *pmatch)
{
	regex_t preg;

	if (regcomp(&preg, pattern, REG_EXTENDED | REG_NEWLINE)) {
		return -1;
	}
	if (preg.re_nsub > SR_RE_MAX_MATCH) {
		regfree(&preg);
		return -2;
	}
	if (regexec(&preg, string, SR_RE_MAX_MATCH, pmatch, 0)) {
		regfree(&preg);
		return -3;
	}
	regfree(&preg);
	return 0;
}


/*! \brief Match pattern against string and, if match succeeds, and replace string
 * with replacement substituting tokens \\d with matched substrings.
 */
static int reg_replace(char *pattern, char *replacement, char *string, char *result)
{
	regmatch_t pmatch[SR_RE_MAX_MATCH];

	if (reg_match(pattern, string, &(pmatch[0]))) {
		return -1;
	}

	return replace(&pmatch[0], string, replacement, result);
}






















/* Takes in a context and returns an ip? */
bool resolve(ResolverContext const * const context, char *buf, size_t buf_sz) {
    bool resolved = false;

    if ((NULL == context) || (NULL == buf)) return false;

    enum { MAX_DOMAIN_NAME_STR_LEN = 666 };
    char dname[MAX_DOMAIN_NAME_STR_LEN] = "";
    naptr_resource_record *nrr_list = NULL;
    naptr_resource_record *nrr = NULL;

    /* Build domain name */
    build_domain_name(context, dname, MAX_DOMAIN_NAME_STR_LEN);

    /* Get all NRRs */
    nrr_list = naptr_query(dname);
    if (NULL == nrr_list) return false;

    /* Remove all the NRRs that don't provide the desired service */
    nrr_list = filter_nrrs(context, nrr_list);

    /* Sort the NRRs so that we can resolve them in order of priority */
    nrr_list = naptr_list_head(nrr_list);
    nrr = naptr_sort(&nrr_list);

    while (nrr != NULL) {
        /* Update domain name */
        transform_domain_name(nrr, dname, MAX_DOMAIN_NAME_STR_LEN);

        /* Go through the NRRs until we get an IP */
        int num_ips = record_lookup(nrr->flag, dname, buf, buf_sz);

        if (0 < num_ips) break;

        nrr = nrr->next;
    }

    naptr_free_resource_record_list(nrr_list);

    return resolved;
}


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

    // resolve(&context0, ipv4, INET_ADDRSTRLEN);
    // printf("========================================\n");
    // printf("The the final resolved IP is '%s'\n", ipv4);
    // resolve(&context1, ipv4, INET_ADDRSTRLEN);
    // printf("========================================\n");
    // printf("The the final resolved IP is '%s'\n", ipv4);
    // resolve(&context2, ipv4, INET_ADDRSTRLEN);
    // printf("========================================\n");
    // printf("The the final resolved IP is '%s'\n", ipv4);
    // resolve(&context3, ipv4, INET_ADDRSTRLEN);
    // printf("========================================\n");
    // printf("The the final resolved IP is '%s'\n", ipv4);
    // resolve(&context4, ipv4, INET_ADDRSTRLEN);
    // printf("========================================\n");
    // printf("The the final resolved IP is '%s'\n", ipv4);


    naptr_resource_record nrr = {
        .regex_pattern = "([a-z0-9]+)(..*)",
        .regex_replace = "\\1.apn.epc.mnc999.mcc999.3gppnetwork.org",
        .replacement = ".",
    };
    char dname[200] = "mms.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";

    // naptr_resource_record nrr = {
    //     .regex_pattern = "fox",
    //     .regex_replace = "\\cat",
    //     .replacement = ".",
    // };
    // char dname[200] = "The quick brown fox jumps over the lazy dog";

    transform_domain_name(&nrr, dname, 200);
    printf("Regex was transformed to       : '%s'\n", dname);
    printf("Regex should be transformed to : 'mms.apn.epc.mnc999.mcc999.3gppnetwork.org'\n");

    return 0;
}


static bool build_domain_name(ResolverContext const * const context, char * const buf, size_t buf_sz) {
    bool build_success = false;
    int chars_written = 0;

    if (0 == strlen(context->apn)) {
        chars_written = snprintf(
            buf,
            buf_sz,
            "%s.epc.mnc%s.mcc%s.%s", 
            context->target,
            context->mnc,
            context->mcc,
            context->domain_suffix
        );
    } else {
        chars_written = snprintf(
            buf,
            buf_sz,
            "%s.apn.epc.mnc%s.mcc%s.%s", 
            context->apn,
            context->mnc,
            context->mcc,
            context->domain_suffix
        );
    }

    if (chars_written < buf_sz) {
        build_success = true;
    }

    return build_success;
}

// todo this needs a little work... itll probably bug out if we try filter with 1 element in the list
static naptr_resource_record * filter_nrrs(ResolverContext const * const context, naptr_resource_record *nrr) {

    if ((NULL == context) || (NULL == nrr)) return NULL;

    nrr = naptr_list_head(nrr);
    naptr_resource_record *next = nrr->next;
    naptr_resource_record *prev = nrr->prev;

    while (NULL != nrr) {
        next = nrr->next;
        prev = nrr->prev;

        if (should_remove(context, nrr)) {
            naptr_remove_resource_record(nrr);
        }
        nrr = next;
    }

    return naptr_list_head(prev);
}

static bool should_remove(ResolverContext const * const context, naptr_resource_record *nrr) {
    bool should_remove = false;

    enum { DESIRED_STR_LEN = 128 };
    char desired_target_string[DESIRED_STR_LEN] = "";
    char desired_service_string[DESIRED_STR_LEN] = "";

    /* Build the strings */
    snprintf(desired_target_string, DESIRED_STR_LEN, "x-3gpp-%s", context->target);
    snprintf(desired_service_string, DESIRED_STR_LEN, "x-%s-%s", context->interface, context->protocol);

    if ((0 != strstr(nrr->service, desired_service_string)) &&
        (0 != strstr(nrr->service, desired_target_string))) {
        /* This peer provides requested target node & service */
        should_remove = false;
    }
    else {
        /* Excluding this peer due to not handling desired service */
        should_remove = true;
    }

    return should_remove;
}

static void transform_domain_name(naptr_resource_record *nrr, char * dname, size_t max_dname_sz) {
    if ((NULL == nrr) || (NULL == dname)) return;

    /* If a Regex Replaces is set on the DNS entry then evaluate it and apply it */
    if ((0 < strlen(nrr->regex_pattern)) &&
        (0 < strlen(nrr->regex_replace))) {
        printf("\tRunning Regex\n");
        printf("\tregex_pattern is %s\n", nrr->regex_pattern);
        printf("\tregex_replace is %s\n", nrr->regex_replace);

        char res[200] = "";

        int r = reg_replace(nrr->regex_pattern, nrr->regex_replace, dname, res);

        printf("res value : %d\n", r);

        strcpy(dname, res);

        // todo fix this so we can actually do regex substitutes
        // substitute(dname, regex_pattern, regex_replace, output);
    } else if (0 != strcmp(nrr->replacement, ".")) {
        printf("\tDoing straight replace\n");
        printf("\tHost replaced with: %s\n", nrr->replacement);
        strncpy(dname, nrr->replacement, max_dname_sz);
    } else {
        printf("\nNo changes made to domain name\n");
    }
}

static int record_lookup(char lookup_type, char * dname, char * buf, size_t buf_sz) {
    int resolv_lookup_type; 
    ns_msg handle;
    ns_rr record;
    unsigned char response[NS_PACKETSZ];
    int ip_count = 0;

    if ('A' == lookup_type) {
        resolv_lookup_type = T_A; 
    } else if ('S' == lookup_type) {
        resolv_lookup_type = T_SRV; 
    } else {
        printf("Unsupported lookup type");
        return 0;
    }

    int response_length, i, result;

    // Send DNS query for A record type
    response_length = res_query(dname, C_IN, resolv_lookup_type, response, NS_PACKETSZ);
    if (response_length < 0) {
        return 0;
    }

    // Initialize message handle
    result = ns_initparse(response, response_length, &handle);
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
            printf("SRV lookup is currently not implemented!\n");
        }
    }

    return ip_count;
}
