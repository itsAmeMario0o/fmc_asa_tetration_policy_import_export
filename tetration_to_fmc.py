#!/bin/env python3

import json
import requests.packages.urllib3
from pprint import pprint
import os, sys
from tqdm import tqdm
from fmc_rest_client import FMCRestClient
from fmc_rest_client import ResourceException
from fmc_rest_client.resources import *
from tetpyclient import RestClient
from TetPolicy2 import Environment, InventoryFilter, Cluster

class NetworkGroup(ObjectResource):
    def __init__(self, name=None, objects=None, literals=None, description=" "):
        super().__init__(name)
        self.objects = objects
        self.literals = literals
        self.description = description

print("Connecting to Tetration to receive configuration")

TET_API_ENDPOINT="https://tetration.svpod.dc-01.com:8443"
TET_API_CREDS="/root/scripts/tetrationSecuredcKey.json"

tetEnv = Environment(TET_API_ENDPOINT,TET_API_CREDS)
restclient = RestClient(TET_API_ENDPOINT,
                            credentials_file=TET_API_CREDS,
                            verify=False)

requests.packages.urllib3.disable_warnings()
resp = restclient.get('/openapi/v1/applications')

if not resp:
    sys.exit("No data returned for Tetration Apps! HTTP {}".format(resp.status_code))

appIDs = []
appNames = []

APP_KEY = "5b59112a497d4f638bc8a761" #OpenCart App
appIDs = [APP_KEY]

#Collect Policies for selected Tetration Apps

tetEnv.loadPolicy(appIDs)
 
#Connect to FMC

fmc_server_url = "https://10.150.0.10:443"
fmc_username = "apiuser2"
fmc_password = "C1sco12345"

print('Connecting to FMC {} ...'.format(fmc_server_url))
fmc = FMCRestClient(fmc_server_url, fmc_username, fmc_password)
print('Connected Successfully')

#Create blank Access Control Policy

fmc_acp = AccessPolicy('Tetration ACP','BLOCK')
fmc_acp = fmc.create(fmc_acp)
print('Created Access Control Policy ' + fmc_acp.name)

#Create Host Objects and Network Group Objects based on Tetration clusters for selected App

app = tetEnv.primaryApps[APP_KEY]
clusters = app.clusters
filters = app.inventoryFilters
policies = app.defaultPolicies

fmc_host_objects = []
fmc_networkgroups = {}
flag = False

for key in clusters.keys():
    cluster = clusters[key]
    fmc_bulk_hosts = []
    fmc_existing_hosts = []
    fmc_hosts = []
    fmc_networkgroup = []
    print(cluster.name)
    pprint(cluster.hosts)
    if cluster.hosts:     #Checking if the cluster configuration is not empty
        for host in cluster.hosts:
            flag = False
            host['name']='tet-'+host['name']
            for x in range(len(fmc_host_objects)):
                if host['name'] == fmc_host_objects[x].name:
                    fmc_existing_hosts.append(fmc_host_objects[x])
                    flag = True
            if not flag:
                fmc_bulk_hosts.append(Host(host['name'],host['ip']))
        print('Creating hosts for cluster {}'.format(cluster.name))
        if len(fmc_bulk_hosts) != 0:
            fmc_hosts = fmc.create(fmc_bulk_hosts)
            fmc_host_objects = fmc_host_objects + fmc_hosts
        if len(fmc_hosts) != 0:
            if len(fmc_existing_hosts) == 0:
                #for i in range(len(fmc_hosts)):
                #    print(fmc_hosts[i].name+' '+fmc_hosts[i].id)
                fmc_networkgroup = fmc.create(NetworkGroup('tet-cluster-'+cluster.uid,fmc_hosts))
            else:
                #print('Existing hosts')
                #for i in range(len(fmc_existing_hosts)):
                #    print(fmc_existing_hosts[i].name,' ',fmc_existing_hosts[i].id)
                #print('New hosts')
                #for i in range(len(fmc_hosts)):
                #    print(fmc_hosts[i].name+' '+fmc_hosts[i].id)
                group = fmc_existing_hosts+fmc_hosts
                fmc_networkgroup = fmc.create(NetworkGroup('tet-cluster-'+cluster.uid,group))
        else:
            if len(fmc_existing_hosts) != 0:
                #for i in range(len(fmc_existing_hosts)):
                #    print(fmc_existing_hosts[i].name,' ',fmc_existing_hosts[i].id)
                fmc_networkgroup = fmc.create(NetworkGroup('tet-cluster-'+cluster.uid,fmc_existing_hosts))
        fmc_networkgroups[cluster.uid] = fmc_networkgroup

fmc_networkgroup = []
for key in filters.keys():
    invFilter = filters[key]
    fmc_bulk_ips = []
    fmc_networkgroup = []
    #print('Inv Filter: '+invFilter.name)
    if invFilter.name != 'securedc-tet':
        if invFilter.ipSet:   #Check if inventory filter is not empty
            print('Creating network group for inv filter {}'.format(invFilter.name))
            for ip in invFilter.ipSet:
                fmc_bulk_ips.append({"type": "Host", "value": ip})
        else:
            for filter in invFilter.filter['filters']:
                if filter['field'] == 'ip':
                    if filter['type'] == 'eq':
                        fmc_bulk_ips.append({"type": "Host", "value": filter['value']})
                    elif filter['type'] == 'subnet':
                        fmc_bulk_ips.append({"type": "Network", "value": filter['value']})
        fmc_networkgroup = fmc.create(NetworkGroup('tet-filter-'+invFilter.uid,[],fmc_bulk_ips))
        fmc_networkgroups[invFilter.uid] = fmc_networkgroup

#Create Access Policy Rules

print('Creating Access Policy Rules for Policy: '+fmc_acp.name)
fmc_rules = []
rule_index = 0
for policy in policies:
    rule = AccessRule('tet-rule-'+str(rule_index),fmc_acp)
    rule_index = rule_index + 1
    if policy.action == 'ALLOW':
        rule.action = policy.action
    else:
        rule.action = 'BLOCK'
    #Check Clusters and InvFilters for source networks
    if policy.consumerFilterID in clusters.keys(): #Is source network a cluster?
        rule.sourceNetworks = {'objects': [fmc_networkgroups[policy.consumerFilterID]]}
        #print('Source network is a cluster')
    elif policy.consumerFilterID in filters.keys(): #Is source network an inventory filter?
        invFilter = filters[policy.consumerFilterID]
        #print('Source network is an inventory filter '+invFilter.name + ' ' + str(len(invFilter.ipSet)))
        nets = []
        if policy.consumerFilterName != 'securedc-tet':
            rule.sourceNetworks = {'objects': [fmc_networkgroups[policy.consumerFilterID]]}
        else:
            rule.sourceNetworks = {'literals': nets}
    #Check Clusters and InvFilters for destination networks
    if policy.providerFilterID in clusters.keys(): #Is destination network is a cluster
        rule.destinationNetworks = {'objects': [fmc_networkgroups[policy.providerFilterID]]}
        #print('Destination network is a cluster')
    elif policy.providerFilterID in filters.keys():  #Is destination network is an inventory filter?
        invFilter = filters[policy.providerFilterID]
        #print('Destination network is a filter '+invFilter.name+' '+str(len(invFilter.ipSet)))
        nets = []
        if policy.providerFilterName != 'securedc-tet':
            rule.destinationNetworks = {'objects': [fmc_networkgroups[policy.providerFilterID]]}
        else:
            rule.destinationNetworks = {'literals': nets}
    #Adding destination ports to the FMC rule
    rule.destinationPorts = {'objects': [],'literals': []}
    for l4param in policy.l4params:
        if policy.consumerFilterName != policy.providerFilterName:
            if (l4param['proto'] == 6) or (l4param['proto'] == 17):
                if l4param['port_min'] == l4param['port_max']: #If protocol is TCP or UDP
                    rule.destinationPorts['literals'].append({'port': str(l4param['port_min']),
                                                            'protocol': str(l4param['proto']),
                                                            'type': 'PortLiteral'})
                else:
                    rule.destinationPorts['literals'].append({"port": str(l4param['port_min'])+'-'+str(l4param['port_max']),
                                                                'protocol': str(l4param['proto']), 'type': 'PortLiteral'})
            elif l4param['proto'] == 1: #If protocol is ICMP
                rule.destinationPorts['literals'].append({"type": "ICMPv4PortLiteral","protocol": "1","icmpType": "Any"})
    fmc_rules.append(rule)

#Push rules to FMC

for fmc_rule in tqdm(fmc_rules):
    fmc_acp_rules = fmc.create(fmc_rule)
print('Rules were created successfully')

