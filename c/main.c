#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>
#include <stdbool.h>


enum { MAX_FLAGS_STR = 8, // TODO WHAT IS THE ACTUAL MAX?
       MAX_REGEX_STR = 128,
       MAX_SERVICE_STR = 128,
       MAX_REPLACEMENT_STR = NS_MAXDNAME };

enum { ORDER_SZ_BYTES = 2,
       PREFERENCE_SZ_BYTES = 2,
       FLAGS_LEN_SZ_BYTES = 1,
       SERVICE_LEN_SZ_BYTES = 1,
       REGEX_LEN_SZ_BYTES = 1 };

typedef struct {
    char target[8];        // "pgw"
    char interface[8];     // "s5"
    char protocol[8];      // "gtp"
    char apn[32];           // "mms"
    char mnc[8];           // "001"
    char mcc[8];           // "100"
    char domain_suffix[64]; // ".3gppnetwork.org.nickvsnetworking.com";
} ResolverContext;

typedef struct {
    int order;
    int preference;
    char flag;
    char service[MAX_SERVICE_STR];
    char regex[MAX_REGEX_STR];
    char replacement[MAX_REPLACEMENT_STR];
} naptr_resource_record;


static bool parse_naptr_resource_record(const unsigned char * buf, uint16_t buf_sz, naptr_resource_record * const nrr);
static int parse_only_naptr_resource_records(ns_msg * const handle, int count, naptr_resource_record * const out_buf, size_t out_buf_sz);
static int dns_naptr_lookup(const char* dname, naptr_resource_record * const out_buf, size_t out_buf_sz);

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

static bool get_regex_pattern(char const * const regex_str, char * const regex_pattern, size_t max_regex_pattern_sz, char * const regex_replace, size_t max_regex_replace_sz) {
    /* Make sure we don't clobber the original */
    char temp[MAX_REGEX_STR] = "";
    strncpy(temp, regex_str, MAX_REGEX_STR);

    /* TODO replace this so we find location of ! and then memcpy them over with specified size */
    char* regex_pattern_ptr = strtok(temp, "!");
    char* regex_replace_ptr = strtok(NULL, "!");

    strncpy(regex_pattern, regex_pattern_ptr, max_regex_pattern_sz);
    strncpy(regex_replace, regex_replace_ptr, max_regex_replace_sz);

    return false;
}

static bool exclude_naptr_resource_record(char const * const nrr_service, char const * const target, char const * const interface, char const * const protocol) {
    bool should_exclude = false;

    /* Check the Service returned is one we care about, if not skip this node as it's no good to us */
    enum { DESIRED_STR_LEN = 128 };
    char desired_target_string[DESIRED_STR_LEN] = "";
    char desired_service_string[DESIRED_STR_LEN] = "";

    /* Build the strings */
    snprintf(desired_target_string, DESIRED_STR_LEN, "x-3gpp-%s", target);
    snprintf(desired_service_string, DESIRED_STR_LEN, "x-%s-%s", interface, protocol);

    printf("desired_target_string  : '%s'\n", desired_target_string);
    printf("desired_service_string : '%s'\n", desired_service_string);

    if ((0 != strstr(nrr_service, desired_service_string)) &&
        (0 != strstr(nrr_service, desired_target_string))) {
        /* Found! */
        printf("\tThis peer provides requested target node & service\n");
    }
    else {
        printf("\tThis peer only handles     %s\n", nrr_service);
        printf("\tThis peer does not target: %s / %s\n", desired_target_string, desired_service_string);
        printf("\tExcluding this peer due to not handling desired service\n");
        should_exclude = true;
    }

    return should_exclude;
}

static void sus_nrr(naptr_resource_record *nrr, char const * const dname, char const * const target, char const * const interface, char const * const protocol) {

    /* If a Regex Replaces is set on the DNS entry then evaluate it and apply it */
    if (0 < strlen(nrr->regex)) {
        printf("\tRunning Regex\n");
        enum { MAX_REGEX_PATTERN_SZ = 128 };
        char regex_pattern[MAX_REGEX_PATTERN_SZ] = "";
        char regex_replace[MAX_REGEX_PATTERN_SZ] = "";
        
        get_regex_pattern(nrr->regex, regex_pattern, MAX_REGEX_PATTERN_SZ, regex_replace, MAX_REGEX_PATTERN_SZ);

        printf("\tregex_pattern is %s\n", regex_pattern);
        printf("\tregex_replace is %s\n", regex_replace);

        // todo fix this so we can actually do regex substitutes
        // substitute(dname, regex_pattern, regex_replace, output);
    }
    /* Else if no Regex Replacement is set */
    else {
        printf("\tNo Regex Replacement required\n");
        // If replacement value is not '.' then leave the value unchanged
        if (strcmp(nrr->replacement, ".") != 0) {
            printf("\tDoing straight replace\n");
            printf("\tHost replaced with: %s\n", nrr->replacement);
        } else {
            printf("\tNo Static Replacement required\n");
        }
    }




    /* todo this can also be the result of a regex replace */
    char * query_host = nrr->replacement;

    /* Depending on the flags this changes the behavior we use */
    if (('A' == nrr->flag) ||
        ('\0' == nrr->flag)) {
        printf("\tPerforming A-Record lookup on host: %s\n", query_host);
    } else if ('S' == nrr->flag) {
        printf("\tPerforming SRV-Record lookup on host %s\n", query_host);
        printf("\t\tI have not implemented this - Sorry\n");
        return;
    } else {
       printf("Invalid flags option set: %c\n", nrr->flag);
       return;
    }

    enum { NRR_BUF_SZ = 16 };
    naptr_resource_record nrr_buf[NRR_BUF_SZ] = {};
    int elements_consumed = 0;

    elements_consumed += dns_naptr_lookup(query_host, &nrr_buf[elements_consumed], NRR_BUF_SZ - elements_consumed);

    for (int i = 0; i < elements_consumed; ++i) {
        printf("\nResult[%i]:\n", i);
        printf("rdata.order: %i\n",        nrr_buf[i].order);
        printf("rdata.preference: %i\n",   nrr_buf[i].preference);
        printf("rdata.flags: '%c'\n",      nrr_buf[i].flag);
        printf("rdata.service: '%s'\n",    nrr_buf[i].service);
        printf("rdata.regexp: '%s'\n",     nrr_buf[i].regex);
        printf("replacement: '%s'\n",      nrr_buf[i].replacement);
        // sus_nrr(&nrr_buf[i], "pgw", "s5", "gtp");
        // sus_nrr(&nrr_buf[i], dname1, "pgw", "s8", "gtp");
    // printf("\n\n");
    }

}

/* Takes in a context and returns an ip? */
void resolve_apn(char const * const target, char const * const interface, char const * const protocol, char const * const apn, char const * const mnc, char const * const mcc) {
    enum { NRR_BUF_SZ = 16 };
    naptr_resource_record nrr_buf[NRR_BUF_SZ] = {};

    // build_domain_name(apn, mnc);
    const char* dname2 = "internet.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    int elements_consumed = dns_naptr_lookup(dname2, &nrr_buf[elements_consumed], NRR_BUF_SZ - elements_consumed);

    for (int i = 0; i < elements_consumed; ++i) {
        sus_nrr(&nrr_buf[i], dname2, target, interface, protocol);
    }
}

static int dns_naptr_lookup(const char* dname, naptr_resource_record * const out_buf, size_t out_buf_sz) {
    unsigned char answer[NS_PACKETSZ];
    ns_msg handle;
    int bytes_received;
    int count;
    int num_nrrs;

    /* Perform NAPTR lookup */
    bytes_received = res_query(dname, ns_c_in, ns_t_naptr, answer, sizeof(answer));
    if (bytes_received <= 0) {
        return 0;
    }

    /* Parse response and process NAPTR records */
    ns_initparse(answer, bytes_received, &handle);
    count = ns_msg_count(handle, ns_s_an);
    num_nrrs = parse_only_naptr_resource_records(&handle, count, out_buf, out_buf_sz);

    return num_nrrs;
}


int main() {
    enum { NRR_BUF_SZ = 16 };
    naptr_resource_record nrr_buf[NRR_BUF_SZ] = {};
    int elements_consumed = 0;

    const char* dname1 = "mms.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    // const char* dname1 = "internet.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    // const char* dname2 = "internet.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    // const char* dname3 = "mms.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";

    elements_consumed += dns_naptr_lookup(dname1, &nrr_buf[elements_consumed], NRR_BUF_SZ - elements_consumed);
    // elements_consumed += dns_naptr_lookup(dname2, &nrr_buf[elements_consumed], NRR_BUF_SZ - elements_consumed);
    // elements_consumed += dns_naptr_lookup(dname3, &nrr_buf[elements_consumed], NRR_BUF_SZ - elements_consumed);

    for (int i = 0; i < elements_consumed; ++i) {
        printf("\nResult[%i]:\n", i);
        printf("rdata.order: %i\n",        nrr_buf[i].order);
        printf("rdata.preference: %i\n",   nrr_buf[i].preference);
        printf("rdata.flags: '%c'\n",      nrr_buf[i].flag);
        printf("rdata.service: '%s'\n",    nrr_buf[i].service);
        printf("rdata.regexp: '%s'\n",     nrr_buf[i].regex);
        printf("replacement: '%s'\n",      nrr_buf[i].replacement);
        if (exclude_naptr_resource_record(nrr_buf[i].service, "pgw", "s8", "gtp"))
            continue;
        sus_nrr(&nrr_buf[i], dname1, "pgw", "s8", "gtp");
    // printf("\n\n");
    }


    ResolverContext ctx = {
        .apn = "mms",
        .domain_suffix = "3gppnetwork.org.nickvsnetworking.com",
        .interface = "s8",
        .mcc = "001",
        .mnc = "001",
        .protocol = "gpt",
        .target = "pgw",
    };

    char buf[66] = "";
    build_domain_name(&ctx, buf, 66);

    printf("'%s'\n", buf);
    


    return 0;
}


static bool parse_naptr_resource_record(const unsigned char * buf, uint16_t buf_sz, naptr_resource_record * const nrr) {
    bool success = false;

    if ((0 != buf) &&
        (0 != nrr))
    {
        int flags_len;
        int service_len;
        int regex_len;
        size_t bytes_consumed = 0;

        nrr->order = ns_get16(&buf[bytes_consumed]);
        bytes_consumed += ORDER_SZ_BYTES;

        nrr->preference = ns_get16(&buf[bytes_consumed]);
        bytes_consumed += PREFERENCE_SZ_BYTES;

        flags_len = buf[bytes_consumed];
        bytes_consumed += FLAGS_LEN_SZ_BYTES;

        /* Assuming that the flag(s) will only be either 'A' or 'S' */
        nrr->flag = buf[bytes_consumed];
        bytes_consumed += flags_len;

        service_len = buf[bytes_consumed];
        bytes_consumed += SERVICE_LEN_SZ_BYTES;

        memcpy(nrr->service, &buf[bytes_consumed], service_len);
        bytes_consumed += service_len;

        regex_len = buf[bytes_consumed];
        bytes_consumed += REGEX_LEN_SZ_BYTES;

        memcpy(nrr->regex, &buf[bytes_consumed], regex_len);
        bytes_consumed += regex_len;

        int bytes_uncompressed = ns_name_uncompress(
            &buf[0],              /* Start of compressed buffer */
            &buf[buf_sz],         /* End of compressed buffer */
            &buf[bytes_consumed], /* Where to start decompressing */
            nrr->replacement,     /* Where to store decompressed value */
            MAX_REPLACEMENT_STR   /* Number of bytes that can be stored in output buffer */
        );

        if (0 <= bytes_uncompressed) {
            success = true;
        }        
    }

    return success;
}


static int parse_only_naptr_resource_records(ns_msg * const handle, int count, naptr_resource_record * const out_buf, size_t out_buf_sz) {
    ns_rr rr;
    int num_nrrs = 0;

    if ((0 == handle)  ||
        (0 == out_buf) ||
        (out_buf_sz < count)) {
        return num_nrrs;
    }

    for (int i = 0; i < count; i++) {
        ns_parserr(handle, ns_s_an, i, &rr);
        if (ns_rr_type(rr) == ns_t_naptr) {
            parse_naptr_resource_record(&rr.rdata[0], rr.rdlength, &out_buf[num_nrrs]);
            ++num_nrrs;
        }
    }

    return num_nrrs;
}