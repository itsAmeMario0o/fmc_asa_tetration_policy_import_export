"""
Standalone application to convert ASA Policy to Tetratin Policy
"""
from apicservice import ConfigDB
import json
import argparse
import csv
import asa
import ipcalc
from tqdm import tqdm
try:
    from sets import Set
except ImportError:
    Set = set
from tetpyclient import RestClient
import requests.packages.urllib3

TET_API_ENDPOINT="https://tetration.svpod.dc-01.com:8443"
TET_API_CREDS="/root/scripts/tetrationSecuredcKey.json"

"""
Main execution routine
"""
parser = argparse.ArgumentParser(description='ASA Config to Tetration')
parser.add_argument('--maxlogfiles', type=int, default=10, help='Maximum number of log files (default is 10)')
parser.add_argument('--debug', nargs='?',
                        choices=['verbose', 'warnings', 'critical'],
                        const='critical',
                        help='Enable debug messages.')
parser.add_argument('--asaconfig', default=None, help='Configuration file')
parser.add_argument('-f',default=False,help='Sets the flag to orun the script in demonstration mode (defauls is full mode)')
parser.add_argument('-s', default='', help='Sets scope name where the filters and applications will be crated.')

args = parser.parse_args()


#Removing "-" from the scope name
scopeName=str(args.s).replace("-","")


if args.asaconfig is None:
    print('%% No ASA configuration file given')    

# Load in the ASA Configuration
fw = asa.ASA()
try:
    with open(args.asaconfig) as config_file:
        config_file = config_file.readlines()
        fw.loadConfig(config_file)
except IOError:
    print('%% Could not load ASA Config file')
except ValueError:
        print('Could not load improperly formatted ASA Config file')

print('Connecting to Tetration')
restclient = RestClient(TET_API_ENDPOINT,
                            credentials_file=TET_API_CREDS,
                            verify=False)
print('Connected Successfully')
requests.packages.urllib3.disable_warnings()

#Get the Default scope ID
resp = restclient.get('/openapi/v1/app_scopes').json()
default_scope_id = [x for x in resp if x['name'] == scopeName][0]['id']

inventory_filters = {}
print("Creating Firewall Objects as Tetration Filters...")
if not args.f:
    for key in tqdm(fw.networkObjects.keys()):
        filters = []
        for ip in fw.networkObjects[key].ipSet():
            filters.append({"field":"ip","type":"eq","value":ip})
        post_data = {"name": 'fw_obj_' + key, "query": {"type":"or","filters":filters},'app_scope_id': default_scope_id}
        resp = restclient.post('/openapi/v1/filters/inventories',json_body=json.dumps(post_data)).json()
        if type(resp) is dict and 'error' in resp.keys():
            print('ERROR: '+resp['error'])
            print('The Inventory Filter {} may already exist. Delete the filter and try again.'.format(post_data['name']))
            print('Refer to instructions in the lab guide or ask lab proctor.')
            raise SystemExit
        inventory_filters[key]=resp['id']

print("Pushing Access Lists to Tetration for Auditing and Simulation...")
absolute_policies = []
if not args.f:
    for acl in fw.accessLists.keys():
        for fwrule in fw.accessLists[acl].rules:
            absolute_policies.append({"consumer_filter_id": inventory_filters[fwrule.source.name],
                "provider_filter_id": inventory_filters[fwrule.dest.name],
                "l4_params": [{'port':[fwrule.port_min,fwrule.port_max],'proto':fwrule.protocol}],
                'action':'ALLOW',
                'priority':50})

    import_json = json.dumps({"author": "dCloud User","primary": 'false',"app_scope_id":default_scope_id,
                              "name":"ASA Firewall Auditing","absolute_policies":absolute_policies,
                              "catch_all_action":"DENY","vrf": {"id": 11,"name": scopeName,"tenant_id": 0,
                              "tenant_name": scopeName}}, indent = 2)
    resp = restclient.post('/openapi/v1/applications',json_body=import_json)
    if type(resp) is dict and 'error' in resp.keys():
        print('ERROR: '+resp['error'])
        print('The Workspace {} may already exist. Delete the workspace and try again.'.format(post_data['name']))
        print('Refer to instructions in the lab guide or ask lab proctor.')
        raise SystemExit
    elif type(resp) is requests.models.Response and  resp.status_code == 200:
        print("Workspace created successfully")
    elif  type(resp) is requests.models.Response:
        print(resp.status_code)
        raise SystemExit

print('ASA configuration is successfully pushed to Tetration')
