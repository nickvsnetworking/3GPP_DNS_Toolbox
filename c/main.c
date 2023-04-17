#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <regex.h>


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

typedef struct naptr_resource_record {
    struct naptr_resource_record* head;
    struct naptr_resource_record* next;

    int og_val;
    int order;
    int preference;
    char flag;
    char service[MAX_SERVICE_STR];
    char regex[MAX_REGEX_STR];
    char replacement[MAX_REPLACEMENT_STR];
} naptr_resource_record;


static bool parse_naptr_resource_record(const unsigned char * buf, uint16_t buf_sz, naptr_resource_record * const nrr);
static int parse_only_naptr_resource_records(ns_msg * const handle, int count, naptr_resource_record * const out_buf, size_t out_buf_sz);
static int dns_naptr_lookup(const char* dname);

static naptr_resource_record * parse_naptr_resource_records(ns_msg * const handle, int count);



static void print_mem(void* ptr, size_t sz) {
    for (int i = 0; i < sz; ++i) {
        printf("%02X ", *(((uint8_t*)ptr) + i));
    }
    printf("\n");
}






/*
 * Tests if one result record is "greater" that the other.  Non-NAPTR records
 * greater that NAPTR record.  An invalid NAPTR record is greater than a 
 * valid one.  Valid NAPTR records are compared based on their
 * (order,preference).
 */
static inline int naptr_greater(naptr_resource_record *na, naptr_resource_record *nb)
{
	if(na == 0)
		return 1;

	if(nb == 0)
		return 0;

    if (na->preference > nb->preference) {
        return 1;
    } else if (na->preference == nb->preference) {
        return na->order >= nb->order;
    }

    return 0;
	// return (((na->order) << 16) + na->preference) > (((nb->order) << 16) + nb->preference);
}


/*
 * Bubble sorts result record list according to naptr (order,preference).
 */
static inline void naptr_sort(naptr_resource_record **head)
{
	naptr_resource_record *p, *q, *r, *s, *temp, *start;

	/* r precedes p and s points to the node up to which comparisons
         are to be made */

	s = NULL;
	start = *head;
	while(s != start->next) {
		r = p = start;
		q = p->next;
		while(p != s) {
			if(naptr_greater(p, q)) {
				if(p == start) {
					temp = q->next;
					q->next = p;
					p->next = temp;
					start = q;
					r = q;
				} else {
					temp = q->next;
					q->next = p;
					p->next = temp;
					r->next = q;
					r = q;
				}
			} else {
				r = p;
				p = p->next;
			}
			q = p->next;
			if(q == s)
				s = p;
        }
	}
	*head = start;
    (*head)->head = start;
}






void print_nrr(naptr_resource_record *nrr) {
    printf("\nResult:\n");
    printf("rdata.preference: %i\n",   nrr->preference);
    printf("rdata.order: %i\n",        nrr->order);
    printf("rdata.flags: '%c'\n",      nrr->flag);
    printf("rdata.service: '%s'\n",    nrr->service);
    printf("rdata.regexp: '%s'\n",     nrr->regex);
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

    elements_consumed += dns_naptr_lookup(query_host);

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
    int elements_consumed = dns_naptr_lookup(dname2);

    for (int i = 0; i < elements_consumed; ++i) {
        sus_nrr(&nrr_buf[i], dname2, target, interface, protocol);
    }
}

/* Returns a linked list of all the  */
static int dns_naptr_lookup(const char* dname) {
    unsigned char answer[NS_PACKETSZ*2];
    ns_msg handle;
    int bytes_received;
    int count;
    int num_nrrs;

    naptr_resource_record *head;
    naptr_resource_record *current;

    /* Perform NAPTR lookup */
    /* NAPTR records serialised in buffer  */
    bytes_received = res_query(dname, ns_c_in, ns_t_naptr, answer, sizeof(answer));
    if (bytes_received <= 0) {
        printf("\nWe didnt get no bytes back :(\n");
        printf("Query: '%s'\n", dname);
        return 0;
    }

    printf("Got a total of %i bytes\n", bytes_received);
    print_mem(&answer, bytes_received);

    /* Parse response and process NAPTR records */
    /* NAPTR records in handler */
    ns_initparse(answer, bytes_received, &handle);
    count = ns_msg_count(handle, ns_s_an);
    printf("We ended up getting %i message back from '%s'\n", count, dname);

    /* NAPTR records in linked list */
    current = parse_naptr_resource_records(&handle, count);

    if (NULL == current) {
        printf("Failed to parse any answers!\n");
        return 0;
    }



    head = current->head;

    printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    printf("Presorted\n");
    printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    int i = 0;
    while (current != NULL) {
        current->og_val = i;
        ++i;
        print_nrr(current);
        current = current->next;
    }

    printf("\n\n\n\n");
    current = head;
    naptr_sort(&current);

    printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
    printf("sorted\n");
    printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
    i = 0;
    while (current != NULL) {
        print_nrr(current);
        printf("Current index in list : %i\n", i);
        printf("Original index in list: %i\n", current->og_val);
        
        ++i;
        current = current->next;
    }


    return num_nrrs;
}


int main() {
    // const char* dname1 = "mms.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    // const char* dname1 = "internet.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    // const char* dname2 = "internet.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    // const char* dname3 = "mms.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";

    // elements_consumed += dns_naptr_lookup(dname1, &nrr_buf[elements_consumed], NRR_BUF_SZ - elements_consumed);
    // elements_consumed += dns_naptr_lookup(dname2, &nrr_buf[elements_consumed], NRR_BUF_SZ - elements_consumed);
    // elements_consumed += dns_naptr_lookup(dname3, &nrr_buf[elements_consumed], NRR_BUF_SZ - elements_consumed);

    // for (int i = 0; i < elements_consumed; ++i) {
    //     printf("\nResult[%i]:\n", i);
    //     printf("rdata.order: %i\n",        nrr_buf[i].order);
    //     printf("rdata.preference: %i\n",   nrr_buf[i].preference);
    //     printf("rdata.flags: '%c'\n",      nrr_buf[i].flag);
    //     printf("rdata.service: '%s'\n",    nrr_buf[i].service);
    //     printf("rdata.regexp: '%s'\n",     nrr_buf[i].regex);
    //     printf("replacement: '%s'\n",      nrr_buf[i].replacement);
    //     if (exclude_naptr_resource_record(nrr_buf[i].service, "pgw", "s8", "gtp"))
    //         continue;
    //     sus_nrr(&nrr_buf[i], dname1, "pgw", "s8", "handlegtp");
    // // printf("\n\n");
    // }


    // ResolverContext ctx = {
    //     .apn = "mms",
    //     .domain_suffix = "3gppnetwork.org.nickvsnetworking.com",
    //     .interface = "s8",
    //     .mcc = "001",
    //     .mnc = "001",
    //     .protocol = "gpt",
    //     .target = "pgw",
    // };

    // char buf[66] = "";
    // build_domain_name(&ctx, buf, 66);

    // printf("'%s'\n", buf);
    
    const char* dname1 = "internet.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    const char* dname2 = "internet.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    const char* dname3 = "mms.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    const char* dname4 = "internet.apn.epc.mnc002.mcc002.3gppnetwork.org.nickvsnetworking.com";

    // dns_naptr_lookup(dname1, &nrr_buf[elements_consumed], NRR_BUF_SZ - elements_consumed);
    // dns_naptr_lookup(dname2, &nrr_buf[elements_consumed], NRR_BUF_SZ - elements_consumed);
    // dns_naptr_lookup(dname3, &nrr_buf[elements_consumed], NRR_BUF_SZ - elements_consumed);
    dns_naptr_lookup(dname4);


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

static naptr_resource_record * parse_naptr_resource_records(ns_msg * const handle, int count) {
    ns_rr rr;
    int num_nrrs = 0;
    naptr_resource_record * nrr_head = NULL;
    naptr_resource_record * nrr_current = NULL;
    naptr_resource_record * nrr_previous = NULL;

    if (0 == handle) {
        return NULL;
    }

    for (int i = 0; i < count; i++) {
        printf("parsing\n");
        ns_parserr(handle, ns_s_an, i, &rr);
        printf("checking if naptr: %i\n", ns_rr_type(rr));
        if (ns_rr_type(rr) == ns_t_naptr) {
            /* Make memory for new nrr */
            nrr_current = (naptr_resource_record*)malloc(sizeof(naptr_resource_record));
            if (NULL == nrr_current) {
                
                printf("Critical failure... Could not allocate memory\n");
                /*  */
                exit(-1);
            }
            memset(nrr_current, 0, sizeof(naptr_resource_record));

            /* Set the nrr data */
            parse_naptr_resource_record(&rr.rdata[0], rr.rdlength, nrr_current);

            printf("nrr_current->preference : %i\n", nrr_current->preference);
            printf("nrr_current->order      : %i\n", nrr_current->order);

            /* If the head doesn't exist then this is the head */
            if (NULL == nrr_head) {
                nrr_head = nrr_current;
            }

            /* Link the NRR to the previous nrr */
            if (NULL != nrr_previous) {
                nrr_previous->next = nrr_current;
            }

            /* The current NRR does not have a next yet */
            nrr_current->next = NULL;
            
            /* Link the NRR to the head nrr */
            nrr_current->head = nrr_head;

            /* Now this NRR is the previous nrr */
            nrr_previous = nrr_current;
        }
    }

    return nrr_head;
}



static void _free_naptr_resource_records(naptr_resource_record * nrr) {
    if (NULL != nrr) {
        /* Use the 'head' to free the 'tail' */
        _free_naptr_resource_records(nrr->next);
        
        /* Free the 'head' */
        free(nrr);
    }
}

static void free_naptr_resource_records(naptr_resource_record * nrr) {
    if (NULL != nrr) {
        /* Make sure we start at the head */
        nrr = nrr->head;
        _free_naptr_resource_records(nrr);
    }
}