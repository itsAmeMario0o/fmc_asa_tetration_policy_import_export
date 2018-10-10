#!/bin/env python3

#!/usr/bin/env python

"""Standalone application to convert FMC Policy to Tetration Policy.
NOTE: this is a Proof of Concept script, please test before using in production!

Copyright (c) 2018 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.0 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

"""

import argparse
import json
import csv
import requests.packages.urllib3
from pprint import pprint
import os, sys
from tqdm import tqdm
from fmc_rest_client import FMCRestClient
from fmc_rest_client import ResourceException
from fmc_rest_client.resources import *
from tetpyclient import RestClient
from TetPolicy2 import Environment, InventoryFilter, Cluster
from __future__ import absolute_import, division, print_function

__author__ = "Oxana Sannikova <osanniko@cisco.com>"
__contributors__ = [
    "Chris Mchenry <chmchenr@cisco.com>"
]
__copyright__ = "Copyright (c) 2018 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.0"

#TO DO: INSERT FMC URL AND CREDENTIALS BELOW
fmc_server_url = "https://URL:PORT"
fmc_username = "USER"
fmc_password = "PWD"

#TO DO: INSERT TETRATION URL AND CREDENTIALS BELOW
TET_API_ENDPOINT="https://URL:PORT"
TET_API_CREDS="FILEPATH/FILENAME.json"

def get_fmc_rest_client():
    global fmc
    print('Connecting to FMC ...')
    fmc = FMCRestClient(fmc_server_url, fmc_username, fmc_password)
    print('Connected Successfully')
    return fmc


class NetworkGroup(ObjectResource):
    def __init__(self, name=None, objects=None, literals=None):
        super().__init__(name)
        self.objects = objects
        self.literals = literals

"""
Main execution routine
"""

parser = argparse.ArgumentParser(description='FMC Config to Tetration')
parser.add_argument('-f', default=False, help='Sets the flag to run the script in demonstration mode (default is full mode)')
parser.add_argument('-s', default='', help='Sets scope name where the filters and applications will be crated. (default None)')


args = parser.parse_args()


#Removing "-" from the scope name
scopeName=str(args.s).replace("-","")
sessionId=str(args.s).split("-")[2]


print('Connecting to Tetration')
restclient = RestClient(TET_API_ENDPOINT,
                            credentials_file=TET_API_CREDS,
                            verify=False)
print('Connected Successfully')
requests.packages.urllib3.disable_warnings()

#Get the Default scope ID
resp = restclient.get('/openapi/v1/app_scopes').json()
default_scope_id = [x for x in resp if x['name'] == scopeName][0]['id']
    
fmc = get_fmc_rest_client()

policies = fmc.list(globals()['AccessPolicy']())
tetration_policy =  [policy  for policy in policies if policy.name=='ACME-SamplePolicy-Scenario1'][0]

rules = fmc.list(AccessRule(container=tetration_policy))
fmc_rules = {rule.id:rule for rule in rules}
    
groups = fmc.list(NetworkGroup())
fmc_groups = {group.id:group for group in groups}
    
hosts = fmc.list(Host())
fmc_hosts = {host.id:host for host in hosts}
    
inventory_filters = {}
absolute_policies = []
filter_any = None
destination_filter = None
    
#Creating default filter
print("Creating Default Filter: ACME_Default_Filter")
if not args.f:
    post_data = {"name": 'ACME_Default_Filter',
                 "query": {"type":"contains","field": "host_name","value": sessionId},
                 "app_scope_id": default_scope_id}
    resp = restclient.post('/openapi/v1/filters/inventories',json_body=json.dumps(post_data)).json()
    if  type(resp) is dict and 'error' in resp.keys():
        print('ERROR: '+resp['error'])
        print('The Defaul Filter may already exist. Delete the filter and try again.\nRefer to instructions in the lab guide or ask lab proctor.')
        raise SystemExit
    filter_any = resp['id']

print("Creating Firewall Objects as Tetration Filters...")

if not args.f:
    for rule in tqdm(fmc_rules.values()):
        rule_source_networks = rule.sourceNetworks['objects']
        rule_destination_networks = rule.destinationNetworks['objects']
        
        if rule_source_networks:
            for network_group in rule_source_networks:
                if network_group['id'] not in inventory_filters.keys():
                    filters = []
                    if network_group['id'] in fmc_groups.keys():
                        objects = fmc_groups[network_group['id']].objects
                        literals = fmc_groups[network_group['id']].literals
                        if objects:
                            for object in objects:
                                filters.append({"field":"ip","type":"eq","value":fmc_hosts[object['id']].value})
                        if literals:
                            for literal in literals:
                                filters.append({"field":"ip","type":"eq","value":literal['value']})
                        post_data = {"name": fmc_groups[network_group['id']].name,
                                     "query": {"type":"or","filters":filters},
                                     "app_scope_id": default_scope_id}
                    elif network_group['id'] in fmc_hosts.keys():
                        filters.append({"field":"ip","type":"eq","value":fmc_hosts[network_group['id']].value})
                        post_data = {"name": fmc_hosts[network_group['id']].name,
                                     "query": {"type":"or","filters":filters},
                                     "app_scope_id": default_scope_id}
                    resp = restclient.post('/openapi/v1/filters/inventories',json_body=json.dumps(post_data)).json()
                    if 'error' in resp.keys():
                        print('ERROR: '+resp['error'])
                        print('The Inventory Filter {} may already exist. Delete the filter and try again.'.format(post_data['name']))
                        print('Refer to instructions in the lab guide or ask lab proctor.')
                        raise SystemExit 
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
                    if network_group['id'] in fmc_groups.keys():
                        objects = fmc_groups[network_group['id']].objects
                        literals = fmc_groups[network_group['id']].literals
                        if objects:
                            for object in objects:
                                filters.append({"field":"ip","type":"eq","value":fmc_hosts[object['id']].value})
                        if literals:
                            for literal in literals:
                                filters.append({"field":"ip","type":"eq","value":literal['value']})
                        post_data = {"name": fmc_groups[network_group['id']].name,
                                     "query": {"type":"or","filters":filters},
                                     "app_scope_id": default_scope_id}
                    elif network_group['id'] in fmc_hosts.keys():
                        filters.append({"field":"ip","type":"eq","value":fmc_hosts[network_group['id']].value})
                        post_data = {"name": fmc_hosts[network_group['id']].name,
                                     "query": {"type":"or","filters":filters},
                                     "app_scope_id": default_scope_id}
                    resp = restclient.post('/openapi/v1/filters/inventories',json_body=json.dumps(post_data)).json()
                    if 'error' in resp.keys():
                        print('ERROR: '+resp['error'])
                        print('The Inventory Filter {} may already exist. Delete the filter and try again.'.format(post_data['name']))
                        print('Refer to instructions in the lab guide or ask lab proctor.')
                        raise SystemExit
                    
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

        protocol = 0
        port_min = 0
        port_max = 0
    
        if 'objects' not in rule.destinationPorts.keys():
            if 'literals' in rule.destinationPorts.keys():
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
if not args.f:
    import_json = json.dumps({"author": "dCloud User","primary": 'false',"app_scope_id":default_scope_id,
        "name":"ACME NGFW Auditing","absolute_policies":absolute_policies,
        "catch_all_action":"DENY","vrf": {"id": 11,"name": scopeName,
        "tenant_id": 0,"tenant_name": scopeName}}, indent = 2)
    resp = restclient.post('/openapi/v1/applications',json_body=import_json)
    if  type(resp) is dict and 'error' in resp.keys():
        print('ERROR: '+resp['error'])
        print('The Workspace {} may already exist in Tetration. Delete the workspace and try again.'.format(post_data['name']))
        print('Refer to instructions in the lab guide or ask lab proctor.')
        raise SystemExit
    elif type(resp) is requests.models.Response and  resp.status_code == 200:
        print("Workspace created successfully")
    elif  type(resp) is requests.models.Response:
        print(resp.status_code)
        raise SystemExit

print("Rules successfully pushed to Tetration")
