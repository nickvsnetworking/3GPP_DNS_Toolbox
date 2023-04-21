import dns.renderer
import dns.resolver
import dns.rrset
#def domainlookup(domain):

def Roaming_Check(mcc, mnc, imsi):
    print("Checking to see if this is a roamer")
    plmn_concatenated = str(mcc) + str(mnc)
    if imsi.startswith(plmn_concatenated):
        print("This is HOME subscriber (S5)")
    else:
        print("This is ROAMING (S8)")
        print("Trying domain")
        search_mcc = imsi[0:3]
        search_mnc = imsi[3:6]
        try:
            domain = "epc.mnc" + str(search_mnc) + ".mcc" + str(search_mcc) + ".3gppnetwork.org"
            print("Searching domain " + str(domain))
            answers = dns.resolver.query(domain, 'NAPTR')
            print(answers)
        except:
            print("failed to find matching domain with 3 digit - Trying with 2")
            search_mcc = search_mcc[0:2]
            domain = "epc.mnc" + str(search_mnc) + ".mcc" + str(search_mcc).zfill(3) + ".3gppnetwork.org"
            answers = dns.resolver.query(domain, 'NAPTR')
            print(answers)


#PLMN from Config File
mcc='001'
mnc='01'

#Home Subscriber (Not Roaming)
imsi = '00101123456789'
Roaming_Check(mcc=mcc, mnc=mnc, imsi=imsi)

#Roaming Subscriber (Roaming)
imsi = '999011123456789'
Roaming_Check(mcc=mcc, mnc=mnc, imsi=imsi)