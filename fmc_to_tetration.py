#!/bin/env python3

import json
import csv
import requests.packages.urllib3
#from terminaltables import AsciiTable
from pprint import pprint
import os, sys
from tqdm import tqdm
#import ipaddress
from fmc_rest_client import FMCRestClient
from fmc_rest_client import ResourceException
from fmc_rest_client.resources import *
from tetpyclient import RestClient
from TetPolicy2 import Environment, InventoryFilter, Cluster

fmc_server_url = "https://128.107.66.87"
fmc_username = "osanniko"
fmc_password = "92937"

TET_API_ENDPOINT="https://medusa-cpoc.cisco.com"
TET_API_CREDS="api_credentials_jefanell.json"

def get_fmc_rest_client():
    global fmc
    #print('Connecting to FMC {}@{} ...'.format(fmc_username, fmc_server_url))
    print('Connecting to FMC ...')
    fmc = FMCRestClient(fmc_server_url, fmc_username, fmc_password)
    print('Connected Successfully')
    return fmc


class NetworkGroup(ObjectResource):
    def __init__(self, name=None, objects=None, literals=None):
        super().__init__(name)
        self.objects = objects
        self.literals = literals

def main():
    """
    Main execution routine
    """
    print('Connecting to Tetration')
    restclient = RestClient(TET_API_ENDPOINT,
                            credentials_file=TET_API_CREDS,
                            verify=False)
    print('Connected Successfully')
    requests.packages.urllib3.disable_warnings()

    #Get the Default scope ID
    resp = restclient.get('/openapi/v1/app_scopes').json()
    default_scope_id = [x for x in resp if x['name'] == 'jefanell-lab:jefanell-mgmt-subnet'][0]['id']
    
    fmc = get_fmc_rest_client()

    policies = fmc.list(globals()['AccessPolicy']())

    rules = fmc.list(AccessRule(container=policies[1]))
    fmc_rules = {rule.id:rule for rule in rules}
    
    groups = fmc.list(NetworkGroup())
    fmc_groups = {group.id:group for group in groups}
    
    hosts = fmc.list(Host())
    fmc_hosts = {host.id:host for host in hosts}
    
    inventory_filters = {}
    absolute_policies = []
    #rule = None
    
    #Creating default filter
    post_data = {"name": "Default","query": {"type":"eq","field": "vrf_id","value": 1},'app_scope_id': default_scope_id}
    resp = restclient.post('/openapi/v1/filters/inventories',json_body=json.dumps(post_data)).json()
    filter_any = resp['id']
    
    print("Creating Firewall Objects as Tetration Filters...")
     
    for rule in fmc_rules.values():
        rule_source_networks = rule.sourceNetworks['objects']
        rule_destination_networks = rule.destinationNetworks['objects']
        
        if rule_source_networks:
            for network_group in rule_source_networks:
                if network_group['id'] not in inventory_filters.keys():
                    filters = []
                    objects = fmc_groups[network_group['id']].objects
                    for object in objects:
                        filters.append({"field":"ip","type":"eq","value":fmc_hosts[object['id']].value})
                    post_data = {"name": fmc_groups[network_group['id']].name,"query": {"type":"or","filters":filters},'app_scope_id': default_scope_id}
                    resp = restclient.post('/openapi/v1/filters/inventories',json_body=json.dumps(post_data)).json()
                    inventory_filters[network_group['id']] = resp['id']
                    source_filter = resp['id']
                else:
                    source_filter = inventory_filters[network_group['id']]
        else:
            source_filter = filter_any
        
        if rule_destination_networks:
            for network_group in rule_destination_networks:
                if network_group['id'] not in inventory_filters.keys():
                    filters = []
                    objects = fmc_groups[network_group['id']].objects
                    for object in objects:
                        filters.append({"field":"ip","type":"eq","value":fmc_hosts[object['id']].value})
                    post_data = {"name": fmc_groups[network_group['id']].name,"query": {"type":"or","filters":filters},'app_scope_id': default_scope_id}
                    resp = restclient.post('/openapi/v1/filters/inventories',json_body=json.dumps(post_data)).json()
                    inventory_filters[network_group['id']] = resp['id']
                    destination_filter = resp['id']
                else:
                    destination_filter = inventory_filters[network_group['id']]
        else:
            destination_filter = filter_any
        
        if rule.action == 'ALLOW':
            action = 'ALLOW'
        else:
            action = 'DENY'
        
        if 'objects' not in rule.destinationPorts.keys():
            if 'literals' not in rule.destinationPorts.keys():
                protocol = 0
                port_min = 0
                port_max = 0
            else:
                for port_literal in rule.destinationPorts['literals']:
                    protocol = int(port_literal['protocol'])
                    if 'port' in port_literal.keys():
                        ports = port_literal['port'].strip().split('-')
                        if len(ports) == 1:
                            port_min = int(ports[0])
                            port_max = port_min
                        else:
                            port_min = int(ports[0])
                            port_max = int(ports[1])
                       
        absolute_policies.append({"consumer_filter_id": source_filter,
                "provider_filter_id": destination_filter,
                "l4_params": [{'port':[port_min,port_max],'proto':protocol}],
                'action':action,
                'priority':50})
                              
    print("Pushing FMC Access Rules to Tetration for Auditing and Simulation...")
    import_json = json.dumps({"author": "Oxana Sannikova","primary": 'true',"app_scope_id":default_scope_id,"name":"NGFW Auditing","absolute_policies":absolute_policies,"catch_all_action":"DENY","vrf": {"id": 1,"name": "Default","tenant_id": 0,"tenant_name": "Default"}}, indent = 2)
    resp = restclient.post('/openapi/v1/applications',json_body=import_json)
                            
if __name__ == '__main__':
    main()