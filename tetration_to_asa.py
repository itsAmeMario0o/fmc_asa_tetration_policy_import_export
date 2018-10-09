"""
Standalone application to convert Tetration Policy to ASA
"""
import json
import csv
from tetpyclient import RestClient
import requests.packages.urllib3
from TetPolicy2 import Environment, InventoryFilter, Cluster
import os
import ipaddress

def main():
    """
    Main execution routine
    """
    
    #TO DO: INSERT TETRATION URL AND API KEY INFO
    TET_API_ENDPOINT="https://URL:PORT"
    TET_API_CREDS="FILEPATH/FILENAME.json"
    
    #TO DO: INSERT APPLICATION KEY BELOW
    APP_KEY = "APPKEY"
    appIDs = [APP_KEY]
    
    #Load Tet Object Model for OpenCart App
    tetEnv = Environment(TET_API_ENDPOINT,TET_API_CREDS)
    requests.packages.urllib3.disable_warnings()
    tetEnv.loadPolicy(appIDs)
    app = tetEnv.primaryApps[APP_KEY]
    clusters = app.clusters
    filters = app.inventoryFilters
    policies = app.defaultPolicies

    configtext = ''
    
    # Load in the IANA Protocols
    protocols = {}
    try:
        with open('/root/scripts/protocol-numbers-1.csv') as protocol_file:
            reader = csv.DictReader(protocol_file)
            for row in reader:
                protocols[row['Decimal']]=row
    except IOError:
        print('%% Could not load protocols file')
        return
    except ValueError:
        print('Could not load improperly formatted protocols file')
        return

    # Load in ASA known ports
    ports = {}
    try:
        with open('/root/scripts/asa_ports.csv') as protocol_file:
            reader = csv.DictReader(protocol_file)
            for row in reader:
                ports[row['Port']]=row
    except IOError:
        print('%% Could not load protocols file')
        return
    except ValueError:
        print('Could not load improperly formatted protocols file')
        return

    #print('\nASA ACL Config\n---------------------------------------\n\n')
    #Process nodes and output information to ASA Objects
    for key in clusters.keys():
        cluster = clusters[key]
        configtext = configtext + "\nobject-group network " + cluster.name.replace(' ','_')
        for ip in cluster.ipSet:
            configtext = configtext +  "\n  host " + ip

    for key in filters.keys():
        invFilter = filters[key]
        if invFilter.name != 'securedc-tet':
            configtext = configtext +  "\nobject-group network " + invFilter.name.replace(' ','_')
            query = invFilter.filter
            #print json.dumps(invFilter.filter)
            for ip in invFilter.ipSet:
                configtext = configtext +  "\n  host " + ip

    configtext = configtext +  '\n!'
    rulestext = ''

    #Process policies and output information as ASA ACL Lines
    #print(len(policies))
    for policy in policies:
        for rule in policy.l4params:
            if policy.consumerFilterName != policy.providerFilterName:
                if rule['proto'] == 1:
                    configtext = configtext +  "\naccess-list ACL_IN extended permit " + protocols[str(rule['proto'])]['Keyword'] + ((" object " + policy.consumerFilterName.replace(' ','_')) if policy.providerFilterName != 'securedc-tet' else " any") + ((" object " + policy.providerFilterName.replace(' ','_')) if policy.providerFilterName != 'securedc-tet' else " any")
                elif (rule['proto'] == 6) or (rule['proto'] == 17):
                    if rule['port_min'] == rule['port_max']:
                        if (str(rule['port_min']) in ports.keys()) and (ports[str(rule['port_min'])]['Proto'] == protocols[str(rule['proto'])]['Keyword'] or ports[str(rule['port_min'])]['Proto'] == 'TCP, UDP'):
                            port = ports[str(rule['port_min'])]['Name']
                        else:
                            port = rule['port_min']
                        configtext = configtext +  "\naccess-list ACL_IN extended permit " + protocols[str(rule['proto'])]['Keyword'] + ((" object " + policy.consumerFilterName.replace(' ','_')) if policy.consumerFilterName != 'securedc-tet' else " any") + ((" object " + policy.providerFilterName.replace(' ','_')) if policy.providerFilterName != 'securedc-tet' else " any") + " eq " + str(port)
                    else:
                        configtext = configtext +  "\naccess-list ACL_IN extended permit " + protocols[str(rule['proto'])]['Keyword'] + ((" object " + policy.consumerFilterName.replace(' ','_')) if policy.consumerFilterName != 'securedc-tet' else " any") + ((" object " + policy.providerFilterName.replace(' ','_')) if policy.providerFilterName != 'securedc-tet' else " any") + " range " + str(rule['port_min']) + "-" + str(rule['port_max'])
                    #rulestext = rulestext +

    configtext = configtext +  "\naccess-list ACL_IN extended deny ip any any\n!\n\n"

    f = open("asa.cfg", "w")
    f.write(configtext)
    f.close()
    print("ASA Configuration file successfully created")

if __name__ == '__main__':
    main()
