"""
NOTE: This is a Proof of Concept script, please test before using in production!

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

from tetpyclient import RestClient
import json
try:
    from sets import Set
except ImportError:
    Set = set
from tqdm import tqdm
from __future__ import absolute_import, division, print_function

__author__ = "Chris Mchenry <chmchenr@cisco.com>"
__contributors__ = [
    "Oxana Sannikova <osanniko@cisco.com>"
]
__copyright__ = "Copyright (c) 2018 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.0"

class AbsolutePolicy(object):
    def __init__(self, policy):
        self._policy = policy
        self._consumerFilterName = policy['consumer_filter_name']
        self._consumerFilterID = policy['consumer_filter_id']
        self._providerFilterName = policy['provider_filter_name']
        self._providerFilterID = policy['provider_filter_id']
        self._action = policy['action']
        self._l4params = []
        for param in policy['l4_params']:
            self._l4params.append({'port_min':param['port'][0],'port_max':param['port'][1],'proto':param['proto']})

    @property
    def action(self):
        return self._action

    @property
    def consumerFilterName(self):
        return self._consumerFilterName

    @property
    def providerFilterName(self):
        return self._providerFilterName

    @property
    def consumerFilterID(self):
        return self._consumerFilterID

    @property
    def providerFilterID(self):
        return self._providerFilterID

    @property
    def l4params(self):
        return self._l4params



class DefaultPolicy(object):
    def __init__(self, policy):
        self._policy = policy
        self._consumerFilterName = policy['consumer_filter_name']
        self._consumerFilterID = policy['consumer_filter_id']
        self._providerFilterName = policy['provider_filter_name']
        self._providerFilterID = policy['provider_filter_id']
        self._action = policy['action']
        self._l4params = []
        for param in policy['l4_params']:
            self._l4params.append({'port_min':param['port'][0],'port_max':param['port'][1],'proto':param['proto']})

    @property
    def action(self):
        return self._action

    @property
    def consumerFilterName(self):
        return self._consumerFilterName

    @property
    def providerFilterName(self):
        return self._providerFilterName

    @property
    def consumerFilterID(self):
        return self._consumerFilterID

    @property
    def providerFilterID(self):
        return self._providerFilterID

    @property
    def l4params(self):
        return self._l4params

class InventoryFilter(object):

    def __init__(self, policy):
        self._name = policy['name']
        self._id = policy['id']
        self._filter = policy['query']
        self._ipSet = Set()
        self._hosts = []
        if 'parent_app_scope' in policy.keys():
            self._parentScope = policy['parent_app_scope']
        else:
            self._parentScope = None

    @property
    def hosts(self):
        return self._hosts

    @property
    def filter(self):
        #print json.dumps(self._filter)
        #return self._filter['filters']
        return self._filter

    @property
    def name(self):
        return self._name

    @property
    def ipSet(self):
        return self._ipSet

    @property
    def uid(self):
        return self._id

    @property
    def parentScope(self):
        return self._parentScope

    @property
    def ipSet(self):
        return self._ipSet

    def resolveFilter(self,environment):
        body = json.dumps({'filter':self._filter})
        #print body
        resp = environment.tetClient.post('/inventory/search',json_body=body)
        if resp:
            ips = resp.json()
            #print ips
            if ips['results'] != None:
                for i in ips['results']:
                    self._ipSet.add(i['ip'])
                    self._hosts.append(i)
        #print(self._ipSet)


class Cluster(object):
    def __init__(self, policy):
        self._name = policy['name']
        self._id = policy['id']
        self._external = policy['external']
        self._ipSet = Set()
        self._hosts = []
        for host in policy['nodes']:
            self._hosts.append(host)
            self._ipSet.add(host['ip'])


    @property
    def hosts(self):
        return self._hosts

    @property
    def name(self):
        return self._name

    @property
    def uid(self):
        return self._id

    @property
    def ipSet(self):
        return self._ipSet

class App(object):
    def __init__(self,environment,app_def):
        self._environment = environment
        self._absolutePolicies = []
        self._defaultPolicies = []
        self._inventoryFilters = {}
        self._clusters = {}
        self._name = app_def['name']
        self._id = app_def['id']
        self._appScopeId = app_def['app_scope_id']
        self._adjacent = False
        self.loadNestedPolicy(app_def)

#    def __init__(self,environment,app_def,adjacent):
#        self._environment = environment
#        self._absolutePolicies = []
#        self._defaultPolicies = []
#        self._inventoryFilters = {}
#        self._clusters = {}
#        self._name = app_def['name']
#        self._id = app_def['id']
#        self._appScopeId = app_def['app_scope_id']
#        self._adjacent = adjacent


    @property
    def absolutePolicies(self):
        return self._absolutePolicies

    @property
    def defaultPolicies(self):
        return self._defaultPolicies

    @property
    def inventoryFilters(self):
        return self._inventoryFilters

    @property
    def clusters(self):
        return self._clusters

    def loadNestedPolicy(self, config):
        print('Resolving Inventory Filters...')
        if 'inventory_filters' in config.keys():
            for inventoryFilter in tqdm(config['inventory_filters']):
                inventoryFilter = InventoryFilter(inventoryFilter)
                inventoryFilter.resolveFilter(self._environment)
                self._inventoryFilters[inventoryFilter.uid] = inventoryFilter
        if 'clusters' in config.keys():
            for cluster in config['clusters']:
                cluster = Cluster(cluster)
                self._clusters[cluster.uid] = cluster
        if 'absolute_policies' in config.keys():
            for policy in config['absolute_policies']:
                self._absolutePolicies.append(AbsolutePolicy(policy))
        if 'default_policies' in config.keys():
            for policy in config['default_policies']:
                self._defaultPolicies.append(DefaultPolicy(policy))

class Environment(object):
    def __init__(self,tetCluster,tetCreds):
        self._primaryApps = {}
        self._adjacentApps = {}
        self._scopes = {}
        self._restclient = RestClient(tetCluster,
                        credentials_file=tetCreds,
                        verify=False)

    @property
    def primaryApps(self):
        return self._primaryApps

    @property
    def adjacentApps(self):
        return self._adjacentApps

    @property
    def tetClient(self):
        return self._restclient

    @property
    def scopes(self):
        return self._scopes

    def addScope(self, scope_id):
        self._scopes['scope']=scope_id

    def loadPolicy(self, appIDs):
        #Load Policy JSON
        for appID in appIDs:
            appDetails = self._restclient.get('/openapi/v1/applications/%s/details'%appID).json()
            #print('\nProcessing "%s"...'%appDetails['name'])
            self._primaryApps[appID] = App(environment=self,app_def=appDetails)
