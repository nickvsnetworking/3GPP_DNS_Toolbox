#This tool (WIP) allows testing and discovery of 3GPP Network elements using DNS
#It can simulate the queries and selection logic run by the MME in finding SGW / PGW peers for S11, S5 & S8 Connectivity
#References: 
# 3GPP TS 129 303 Section 5 
# GSMA IR.88 - Section 3.2
# https://www.cisco.com/c/en/us/support/docs/wireless/asr-5000-series/119178-ts-dns-asr-00.html

import dns.renderer
import dns.resolver
import dns.rrset
import re
import sys

#Preconfigured Entries

#Scenario 1
target = 'pgw'
interface = 's5'
protocol = 'gtp' 
query_host_original = 'internet.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com'
#This returns 2 NAPTR records, one of which only handles S8 so is excluded, the other does a simple A record lookup
#and gets back two possible IPs to send the traffic to (10.1.1.1 and 10.7.15.1)

#Scenario 2
target = 'pgw'
interface = 's8'
protocol = 'gtp' 
query_host_original = 'internet.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com'
#This returns 2 NAPTR records, one of which only handles S5 so is excluded, the other does a simple A record lookup
#and gets back two possible IPs to send the traffic to (10.1.1.1 and 10.7.15.1)

# #Scenario 3
# target = 'pgw'
# interface = 's8'
# protocol = 'gtp' 
# query_host_original = 'internet2.apn.epc.mnc001.mcc001.3gppnetwork.org.nickvsnetworking.com'
# #This returns 5 NAPTR records
# #One option transforms into test_ims



answers = dns.resolver.query(query_host_original, 'NAPTR')
print("Got back " + str(len(answers)) + " results for query " + str(query_host_original))
for rdata in answers:
    query_host = query_host_original
    print("\nResult:")
    print("rdata.order: " + str(rdata.order))
    print("rdata.preference: " + str(rdata.preference))
    print("rdata.flags: " + str(rdata.flags))
    print("rdata.regexp: " + str(rdata.regexp))
    print("rdata.replacement: " + str(rdata.replacement))
    print("rdata.service: " + str(rdata.service))

    #Check the Service returned is one we care about, if not bail out
    desired_service_string = 'x-3gpp-' + str(target) + ":x-" + str(interface) + "-" + str(protocol)
    if desired_service_string != rdata.service.decode("utf-8"):
        print("This peer only handles     " + str(rdata.service.decode("utf-8")))
        print("This peer does not handle: " + str(desired_service_string))
        print("Excluding this peer due to not handling desired service")
        continue

    if len(rdata.regexp) !=0:
        print("\tRunning Regex")
        try:
            regex_pattern = rdata.regexp.decode("utf-8").split('!')[1]
            regex_replace = rdata.regexp.decode("utf-8").split('!')[2]
            print("\tregex_pattern is " + str(regex_pattern))
            print("\tregex_replace is " + str(regex_replace))
            print("\tInput is " + str(type(query_host_original)))
        except:
            print("Failed to parse Regex as per NAPTR Rules")
        result = re.sub(
            regex_pattern, 
            regex_replace, 
            query_host_original
        )
        if query_host_original != result:
            print("\tRegex transformed to: " + str(result))
            query_host = result
        else:
            print("Regex transformation failed")
    elif len(rdata.regexp) !=0:

        print("\tNo Regex Replacement required")
        if rdata.replacement != ".":
            print("\tDoing straight replace")
            query_host = rdata.replacement
            print("\tHost replaced with: " + str(query_host))

    #Depending on the flags this changes the behavior we use
    if "A" == rdata.flags.decode("utf-8") or "" == rdata.flags.decode("utf-8"):
        print("\tPerforming A-Record lookup on host: " + str(query_host))
        lookup_type = "A"
    elif "S" == rdata.flags.decode("utf-8"):
        print("\tPerforming SRV-Record lookup on host " + str(query_host))
        lookup_type = "SRV"
        print("\t\tI have not implimented this - Sorry")
        continue
    else:
        print("Invalid flags option set: " + str(rdata.flags))  

    try:
        host_answers = dns.resolver.query(query_host, lookup_type)
    except:
        print("\t\tDNS lookup failed - Domain does not exist")
        continue
    if lookup_type == "SRV":
        for srv_rdata in host_answers:
            print("\t\tSRV Lookup got back Host:")
            print(srv_rdata)
    elif lookup_type == "A":
        print("\t\tA Lookup got back " + str(len(list(host_answers.rrset))) + " hosts:")
        for host in list(host_answers.rrset):
            print("\t\t\tFinal Host: " + str(host))
