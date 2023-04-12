#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>
#include <stdbool.h>


enum { MAX_FLAGS_STR = 8, // TODO WHAT IS THE ACTUAL MAX?
       MAX_REGEX_STR = 128,
       MAX_SERVICE_STR = 128 };


typedef struct {
    int order;
    int preference;
    char flags[MAX_FLAGS_STR];
    char service[MAX_SERVICE_STR];
    char regex[MAX_REGEX_STR];
    char replacement[NS_MAXDNAME];
} naptr_resource_record;


static bool parse_naptr_resource_record(const unsigned char * buf, uint16_t buf_sz, naptr_resource_record * const nrr);
static void parse_only_naptr_resource_records(ns_msg * const handle, int count);


void resolve_apn(const char* dname) {
    unsigned char answer[NS_PACKETSZ];
    ns_msg handle;
    int bytes_received;
    int count;

    // perform NAPTR lookup
    bytes_received = res_query(dname, ns_c_in, ns_t_naptr, answer, sizeof(answer));

    if (bytes_received <= 0) {
        return;
    }

    // parse response and process NAPTR records
    ns_initparse(answer, bytes_received, &handle);
    count = ns_msg_count(handle, ns_s_an);

    parse_only_naptr_resource_records(&handle, count); // todo all output array

    printf("\n\nGot back %i results for query %s:\n", count, dname);

}


int main() {
    const char* dname1 = "internet.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    const char* dname2 = "internet.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    const char* dname3 = "mms.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";

    resolve_apn(dname1);
    resolve_apn(dname2);
    resolve_apn(dname3);

    return 0;
}


static bool parse_naptr_resource_record(const unsigned char * buf, uint16_t buf_sz, naptr_resource_record * const nrr) {
    bool success = false;

    if ((0 != buf) &&
        (0 != nrr))
    {
        size_t bytes_consumed = 0;
        int flags_len = 0;
        int service_len = 0;
        int regex_len = 0;

        nrr->order = ns_get16(&buf[bytes_consumed]);
        bytes_consumed += 2;

        nrr->preference = ns_get16(&buf[bytes_consumed]);
        bytes_consumed += 2;

        flags_len = buf[bytes_consumed];
        bytes_consumed += 1;

        memcpy(nrr->flags, &buf[bytes_consumed], flags_len);
        bytes_consumed += flags_len;

        service_len = buf[bytes_consumed];
        bytes_consumed += 1;

        memcpy(nrr->service, &buf[bytes_consumed], service_len);
        bytes_consumed += service_len;

        regex_len = buf[bytes_consumed];
        bytes_consumed += 1;

        memcpy(nrr->regex, &buf[bytes_consumed], regex_len);
        bytes_consumed += regex_len;

        int bytes_uncompressed = ns_name_uncompress(
            &buf[0],              /* Start of compressed buffer */
            &buf[buf_sz],         /* End of compressed buffer */
            &buf[bytes_consumed], /* Where to start decompressing */
            nrr->replacement,     /* Where to store decompressed value */
            NS_MAXDNAME           /* Number of bytes that can be stored in output buffer */
        );

        if (0 <= bytes_uncompressed) {
            success = true;
        }        
    }

    return success;
}


static void parse_only_naptr_resource_records(ns_msg * const handle, int count) {
    ns_rr rr;

    for (int i = 0; i < count; i++) {
        ns_parserr(handle, ns_s_an, i, &rr);
        if (ns_rr_type(rr) == ns_t_naptr) {
            naptr_resource_record nrr = {};
            parse_naptr_resource_record(&rr.rdata[0], rr.rdlength, &nrr);

            printf("\nResult:\n");
            printf("rdata.order: %i\n",        nrr.order);
            printf("rdata.preference: %i\n",   nrr.preference);
            printf("rdata.flags: '%s'\n",      nrr.flags);
            printf("rdata.service: '%s'\n",    nrr.service);
            printf("rdata.regexp: '%s'\n",     nrr.regex);
            printf("replacement: '%s'\n",      nrr.replacement);
        }
    }

}