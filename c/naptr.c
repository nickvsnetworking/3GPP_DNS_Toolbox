#include "naptr.h"
#include <arpa/inet.h>
#include <resolv.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>


enum { ORDER_SZ_BYTES = 2,
       PREFERENCE_SZ_BYTES = 2,
       FLAGS_LEN_SZ_BYTES = 1,
       SERVICE_LEN_SZ_BYTES = 1,
       REGEX_LEN_SZ_BYTES = 1 };


static naptr_resource_record * parse_naptr_resource_records(ns_msg * const handle, int count);
static bool parse_naptr_resource_record(const unsigned char * buf, uint16_t buf_sz, naptr_resource_record * const nrr);
static void get_regex_pattern_replace(char * const regex_str, char * const regex_pattern, size_t max_regex_pattern_sz, char * const regex_replace, size_t max_regex_replace_sz);
static inline int naptr_greater(naptr_resource_record *na, naptr_resource_record *nb);
static void _naptr_free_resource_record_list(naptr_resource_record * head);


naptr_resource_record * naptr_query(const char* dname) {
    unsigned char answer[NS_PACKETSZ*2];
    ns_msg handle;
    int bytes_received;
    int count;
    int num_nrrs;
    naptr_resource_record *nrrs;


    /* Perform NAPTR lookup */
    /* NAPTR records serialised in buffer  */
    bytes_received = res_query(dname, ns_c_in, ns_t_naptr, answer, sizeof(answer));
    if (bytes_received <= 0) {
        printf("Query failed: '%s'\n", dname);
        return 0;
    }

    /* Parse response and process NAPTR records */
    /* NAPTR records in handler */
    ns_initparse(answer, bytes_received, &handle);
    count = ns_msg_count(handle, ns_s_an);

    /* NAPTR records in linked list */
    nrrs = parse_naptr_resource_records(&handle, count);

    if (NULL == nrrs) {
        printf("Failed to parse any answers!\n");
        return 0;
    }

    return nrrs;
}

/*
 * Bubble sorts result record list according to naptr (order,preference).
 * Returns head to sorted list.
 */
naptr_resource_record * naptr_sort(naptr_resource_record **head)
{
    int swapped;
    naptr_resource_record* current;
    naptr_resource_record* temp;

    if (*head == NULL)
        return NULL;

    do {
        swapped = 0;
        current = *head;

        while (current->next != NULL) {
            if (naptr_greater(current, current->next)) {
                if (current == *head) {
                    *head = current->next;
                    (*head)->prev = NULL;
                } else {
                    current->prev->next = current->next;
                    current->next->prev = current->prev;
                }

                temp = current->next->next;
                current->next->next = current;
                current->prev = current->next;
                current->next = temp;
                if (temp != NULL)
                    temp->prev = current;

                swapped = 1;
            } else {
                current = current->next;
            }
        }
    } while (swapped);

    return *head;
}

naptr_resource_record * naptr_list_head(naptr_resource_record * nrr) {

    if (NULL == nrr) {
        return NULL;
    }

    while (NULL != nrr->prev) {
        nrr = nrr->prev;
    }

    return nrr;
}

void naptr_remove_resource_record(naptr_resource_record * nrr) {
    
    naptr_resource_record *prev = nrr->prev;
    naptr_resource_record *next = nrr->next;

    if (NULL != prev) {
        prev->next = next;
    }

    if (NULL != next) {
        next->prev = prev;
    }

    free(nrr);
}

void naptr_free_resource_record_list(naptr_resource_record * nrr) {
    if (NULL != nrr) {
        /* Make sure we start at the head */
        nrr = naptr_list_head(nrr);
        _naptr_free_resource_record_list(nrr);
    }
}

int naptr_resource_record_list_count(naptr_resource_record * nrr) {
    int count = 0;

    nrr = naptr_list_head(nrr);
    while (NULL != nrr) {
        ++count;
        nrr = nrr->next;
    }

    return count;
}

/* Returns the head of a doubly linked list */
static naptr_resource_record * parse_naptr_resource_records(ns_msg * const handle, int count) {
    ns_rr rr;
    int num_nrrs = 0;
    naptr_resource_record * nrr_current = NULL;
    naptr_resource_record * nrr_next = NULL;

    if (0 == handle) {
        return NULL;
    }

    for (int i = 0; i < count; i++) {
        ns_parserr(handle, ns_s_an, i, &rr);
        if (ns_rr_type(rr) == ns_t_naptr) {
            /* Make memory for new nrr */
            nrr_current = (naptr_resource_record*)malloc(sizeof(naptr_resource_record));
            if (NULL == nrr_current) {
                printf("Critical failure... Could not allocate memory\n");
                exit(-1);
            }
            memset(nrr_current, 0, sizeof(naptr_resource_record));

            /* Set the current NRRs data */
            parse_naptr_resource_record(&rr.rdata[0], rr.rdlength, nrr_current);

            /* This NRR will be added to the start of the list,
             * meaning that the next NRR will be the one we created
             * in the previous iteration. */
            if (NULL != nrr_next) {
                nrr_current->next = nrr_next;
                nrr_next->prev = nrr_current;
            }

            /* The previous NRR doesn't exist yet */
            nrr_current->prev = NULL;

            /* Now this NRR will be the next for the NRR created in the
             * following iteration */
            nrr_next = nrr_current;
        }
    }

    return naptr_list_head(nrr_current);
}

static bool parse_naptr_resource_record(const unsigned char * buf, uint16_t buf_sz, naptr_resource_record * const nrr) {
    bool success = false;

    if ((0 != buf) &&
        (0 != nrr))
    {
        /* Num of '!' chars is 3 */
        enum { MAX_REGEX_STR = MAX_REGEX_PATTERN_STR + MAX_REGEX_REPLACE_STR + 3 };
        int flags_len;
        int service_len;
        int regex_len;
        size_t bytes_consumed = 0;
        char regex[MAX_REGEX_STR] = "";

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

        memcpy(regex, &buf[bytes_consumed], regex_len);
        bytes_consumed += regex_len;

        int bytes_uncompressed = ns_name_uncompress(
            &buf[0],              /* Start of compressed buffer */
            &buf[buf_sz],         /* End of compressed buffer */
            &buf[bytes_consumed], /* Where to start decompressing */
            nrr->replacement,     /* Where to store decompressed value */
            MAX_REPLACEMENT_STR   /* Number of bytes that can be stored in output buffer */
        );

        get_regex_pattern_replace(regex, nrr->regex_pattern, MAX_REGEX_PATTERN_STR, nrr->regex_replace, MAX_REGEX_REPLACE_STR);

        if (0 <= bytes_uncompressed) {
            success = true;
        }        
    }

    return success;
}

/* This will mutate regex_str */
static void get_regex_pattern_replace(char * const regex_str, char * const regex_pattern, size_t max_regex_pattern_sz, char * const regex_replace, size_t max_regex_replace_sz) {
    if ((NULL == regex_str)     ||
        (NULL == regex_pattern) ||
        (NULL == regex_replace)) {
        return;
    }
    
    char* regex_pattern_ptr = strtok(regex_str, "!");
    if (NULL == regex_pattern_ptr) return;

    char* regex_replace_ptr = strtok(NULL, "!");
    if (NULL == regex_replace_ptr) return;

    strncpy(regex_pattern, regex_pattern_ptr, max_regex_pattern_sz);
    strncpy(regex_replace, regex_replace_ptr, max_regex_replace_sz);
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
}

static void _naptr_free_resource_record_list(naptr_resource_record * head) {
    if (NULL != head) {
        /* Use the 'head' to free the 'tail' */
        _naptr_free_resource_record_list(head->next);
        
        /* Free the 'head' */
        free(head);
    }
}
