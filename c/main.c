#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>


void foo(const char* dname) {
    unsigned char answer[NS_PACKETSZ];
    ns_msg handle;
    ns_rr rr; // resource record
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
    printf("Got back %i results for query %s:\n", count, dname);

    for (int i = 0; i < count; i++) {
        ns_parserr(&handle, ns_s_an, i, &rr);
        if (ns_rr_type(rr) == ns_t_naptr) {
            size_t bytes_consumed = 0;

            int order = ns_get16(&rr.rdata[bytes_consumed]);
            bytes_consumed += 2;

            int preference = ns_get16(&rr.rdata[bytes_consumed]);
            bytes_consumed += 2;

            int flags_len = ns_rr_rdata(rr)[bytes_consumed];
            bytes_consumed += 1;

            char flags[8] = "";
            memcpy(flags, &rr.rdata[bytes_consumed], flags_len);
            bytes_consumed += flags_len;

            int service_len = ns_rr_rdata(rr)[bytes_consumed];
            bytes_consumed += 1;

            char service[128] = "";
            memcpy(service, &rr.rdata[bytes_consumed], service_len);
            bytes_consumed += service_len;

            int regex_len = ns_rr_rdata(rr)[bytes_consumed];
            bytes_consumed += 1;

            char regex[128] = "";
            memcpy(regex, &rr.rdata[bytes_consumed], regex_len);
            bytes_consumed += regex_len;

            char replacement[NS_MAXDNAME] = "";
            int bytes_uncompressed = ns_name_uncompress(
                &rr.rdata[0],              /* Start of compressed buffer */
                &rr.rdata[rr.rdlength],    /* End of compressed buffer */
                &rr.rdata[bytes_consumed], /* Where to start decompressing */
                replacement,               /* Where to store decompressed value */
                NS_MAXDNAME                /* Number of bytes that can be stored in output buffer */
            );

            if (-1 == bytes_uncompressed) {
                // throw error?
            }

            printf("\nResult:\n");
            printf("rdata.order: %i\n",        order);
            printf("rdata.preference: %i\n",   preference);
            printf("rdata.flags: '%s'\n",      flags);
            printf("rdata.service: '%s'\n",    service);
            printf("rdata.regexp: '%s'\n",     regex);
            printf("replacement: '%s'\n",     replacement);
        }
    }
}


int main() {
    // const char* dname1 = "internet.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    // const char* dname2 = "internet.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";
    const char* dname3 = "mms.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com";

    // foo(dname1);
    // foo(dname2);
    foo(dname3);

    return 0;
}
