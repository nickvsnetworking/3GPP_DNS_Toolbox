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
    int order;
    int preference;
    char flags[MAX_FLAGS_STR];
    char service[MAX_SERVICE_STR];
    char regex[MAX_REGEX_STR];
    char replacement[MAX_REPLACEMENT_STR];
} naptr_resource_record;


static bool parse_naptr_resource_record(const unsigned char * buf, uint16_t buf_sz, naptr_resource_record * const nrr);
static int parse_only_naptr_resource_records(ns_msg * const handle, int count, naptr_resource_record * const out_buf, size_t out_buf_sz);


int resolve_apn(const char* dname, naptr_resource_record * const out_buf, size_t out_buf_sz) {
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

    const char* dname1 = "internet.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    const char* dname2 = "internet.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    const char* dname3 = "mms.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";

    // elements_consumed += resolve_apn(dname1, &nrr_buf[elements_consumed], NRR_BUF_SZ - elements_consumed);
    elements_consumed += resolve_apn(dname2, &nrr_buf[elements_consumed], NRR_BUF_SZ - elements_consumed);
    // elements_consumed += resolve_apn(dname3, &nrr_buf[elements_consumed], NRR_BUF_SZ - elements_consumed);

    for (int i = 0; i < elements_consumed; ++i) {
        printf("\nResult[%i]:\n", i);
        printf("rdata.order: %i\n",        nrr_buf[i].order);
        printf("rdata.preference: %i\n",   nrr_buf[i].preference);
        printf("rdata.flags: '%s'\n",      nrr_buf[i].flags);
        printf("rdata.service: '%s'\n",    nrr_buf[i].service);
        printf("rdata.regexp: '%s'\n",     nrr_buf[i].regex);
        printf("replacement: '%s'\n",      nrr_buf[i].replacement);
    }

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

        memcpy(nrr->flags, &buf[bytes_consumed], flags_len);
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