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
import pprint

#Preconfigured Entries



def Resolve_APN(target, interface, protocol, apn, mnc, mcc, domain_suffix='.3gppnetwork.org.nickvsnetworking.com'):
    query_host_original = ''
    if len(apn) == 0:
        query_host_original = str(target) + '.epc.mnc' + str(mnc).zfill(3) + '.mcc' + str(mnc).zfill(3) + str(domain_suffix)
    else:
        query_host_original = str(apn) + '.apn.epc.mnc' + str(mnc).zfill(3) + '.mcc' + str(mnc).zfill(3) + str(domain_suffix)

    answers = dns.resolver.query(query_host_original, 'NAPTR')
    print("Got back " + str(len(answers)) + " results for query " + str(query_host_original))
    result_list = []
    for rdata in answers:
        query_host = query_host_original
        print("\nResult:")
        print("rdata.order: " + str(rdata.order))
        print("rdata.preference: " + str(rdata.preference))
        print("rdata.flags: " + str(rdata.flags))
        print("rdata.regexp: " + str(rdata.regexp))
        print("rdata.replacement: " + str(rdata.replacement))
        print("rdata.service: " + str(rdata.service))

        #Check the Service returned is one we care about, if not skip this node as it's no good to us
        desired_target_string = 'x-3gpp-' + str(target)
        desired_service_string = "x-" + str(interface) + "-" + str(protocol)
        if (str(desired_service_string) in str(rdata.service.decode("utf-8"))) and (str(desired_target_string) in str(rdata.service.decode("utf-8"))):
            print("\tThis peer provides requested target node & service")
        else:
            print("\tThis peer only handles     " + str(rdata.service.decode("utf-8")))
            print("\tThis peer does not target: " + str(desired_target_string) + " / " + str(desired_service_string))
            print("\tExcluding this peer due to not handling desired service")
            continue

        #If a Regex Replaces is set on the DNS entry then evaluate it and apply it
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
            
            #Run the Regex Transformation
            result = re.sub(
                regex_pattern, 
                regex_replace, 
                query_host_original
            )

            #Only update the host if the value changed - If Regex changed nothing then we don't need to replace it
            if query_host_original != result:
                print("\tRegex transformed to: " + str(result))
                query_host = result
            else:
                print("Regex transformation failed to match / replace")

        #Else if no Regex Replacement is set
        else:
            print("\tNo Regex Replacement required")
            #If replacement value is not '.' then leave the value unchanged
            if str(rdata.replacement) != ".":
                print("\tDoing straight replace")
                query_host = rdata.replacement
                print("\tHost replaced with: " + str(query_host))
            else:
                print("\tNo Static Replacement required")

        #Depending on the flags this changes the behavior we use
        if "A" == rdata.flags.decode("utf-8") or "" == rdata.flags.decode("utf-8"):
            print("\tPerforming A-Record lookup on host: " + str(query_host))
            lookup_type = "A"
        elif "S" == rdata.flags.decode("utf-8"):
            print("\tPerforming SRV-Record lookup on host " + str(query_host))
            lookup_type = "SRV"
            print("\t\tI have not implemented this - Sorry")
            continue
        else:
            print("Invalid flags option set: " + str(rdata.flags))  

        try:
            host_answers = dns.resolver.query(query_host, lookup_type)
        except:
            print("\t\tDNS lookup failed - Domain '" + str(query_host) + "'does not exist")
            continue
        if lookup_type == "SRV":
            for srv_rdata in host_answers:
                print("\t\tSRV Lookup got back Host:")
                print(srv_rdata)
        elif lookup_type == "A":
            print("\t\tA Lookup got back " + str(len(list(host_answers.rrset))) + " hosts:")
            for host in list(host_answers.rrset):
                print("\t\t\tFinal Host: " + str(host))
                res_dict = {
                    'order': int(rdata.order),
                    'preference' : int(rdata.preference),
                    'host' : str(host)
                }
                result_list.append(res_dict)


    return result_list


IP_List = Resolve_APN(target='pgw', interface='s8', protocol='gtp', apn='mms', mnc='001', mcc='001')
pprint.pprint(IP_List)

IP_List = Resolve_APN(target='pgw', interface='s5', protocol='gtp', apn='internet', mnc='001', mcc='001')
pprint.pprint(IP_List)

IP_List = Resolve_APN(target='pgw', interface='s5', protocol='gtp', apn='mms', mnc='001', mcc='001')
pprint.pprint(IP_List)