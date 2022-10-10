import os
import requests
import json
import time
import base64



CLUSTER_CREATE_TEMPLATE = {
    "account_settings": {
        "enable_compute": True,
        "enable_storage": False,
        "enable_service_catalog": True,
        "enable_kubernetes_dlcm": True,
        "enable_kubernetes_k3s": True,
        "enable_kubernetes_capi": True,
        "providers_enable_gcp": True,
        "providers_enable_aws": True,
        "providers_enable_ali": True,
        "providers_enable_azure": True,
        "providers_enable_onprem": True,
        "providers_enable_openstack": True,
        "providers_enable_arm": True
    },
    "clusterName": "",
    "clusterDescription": "",
    "clusterContact": "test-automation@daiteap.com",
    "kubernetesConfiguration": {
        "version": "v1.19.7",
        "serviceAddresses": "10.233.0.0/18",
        "podsSubnet": "10.233.64.0/18",
        "networkPlugin": "flannel"
    },
    "alicloudSelected": False,
    "awsSelected": False,
    "googleSelected": False,
    "openstackSelected": False,
    "azureSelected": False,
    "onpremiseSelected": False,
    "iotarmSelected": False,
    # "aws": {
    #     "account": "aws-daiteap_dev",
    #     "region": "eu-west-1",
    #     "nodes": [
    #         # {
    #         #     "is_control_plane": true,
    #         #     "zone": "europe-west1-b",
    #         #     "instanceType": "n1-standard-8",
    #         #     "operatingSystem": "debian-cloud/debian-10-buster-v20211209"
    #         # }
    #     ],
    #     "vpcCidr": "10.10.0.0/16"
    # },
    # "google": {
    #     "account": "",
    #     "region": "us-east1",
    #     "zone": "us-east1-b",
    #     "instanceType": "c2d-highcpu-8",
    #     "operatingSystem": "debian-cloud/debian-9-stretch-v20211209",
    #     "nodes": [
    #         # {
    #         #     "is_control_plane": false,
    #         #     "zone": "europe-west1-b",
    #         #     "instanceType": "n1-standard-8",
    #         #     "operatingSystem": "debian-cloud/debian-10-buster-v20211209"
    #         # }
    #     ],
    #     "vpcCidr": "10.30.0.0/16"
    # },
    "load_balancer_integration": "",
    "internal_dns_zone": "daiteap.internal",
    "type": 1,
    "name": "",
    "description": "",
    "contact": "test-automation@daiteap.com",
    "projectId": "697a1ee4-8469-48e9-99d5-b17fbbebb273"
}

def initConfig():
    username = os.getenv('DAITEAP_USERNAME', None)
    password = os.getenv('DAITEAP_PASSWORD', None)
    url = os.getenv('PLATFORM_URL', None)
    session = requests.Session()
    session.auth = (username, password)
    return session, url


def createFromTemplates(session, url):
    print(url)
    created_cluster_ids = []
    #### create from templates
    r = session.get(str(url)+"/server/environmenttemplates/list",headers={"content-type":"application/json"})
    if r.status_code == 200:
        # print(r.text)
        templates = json.loads(r.text)
        for template in templates["environmentTemplates"]:
            r2 = session.get(url+"/server/environmenttemplates/get/"+template['id'],headers={"content-type":"application/json"})
            if r2.status_code == 200:
                # print("Details for template ", template['name'])
                # print(r2.text)
                template_details = json.loads(r2.text)
                # print("--- TEMPLATE", template_details, "\n")
                payload_create = CLUSTER_CREATE_TEMPLATE
                payload_create['kubernetesConfiguration'] = template_details['config']['kubernetesConfiguration']
                payload_create['load_balancer_integration'] = template_details['config']['load_balancer_integration']
                payload_create['internal_dns_zone'] = template_details['config']['internal_dns_zone']
                payload_create['clusterName'] = template_details['name']
                payload_create['clusterDescription'] = template_details['description']
                payload_create['clusterContact'] = template_details['contact']
                payload_create['type'] = template_details['type']
                # payload_create['account'] = template_details['account']
                
                if 'aws' in template_details['config']:
                    payload_create['awsSelected'] = True
                    key = 'aws'

                if 'google' in template_details['config']:
                    payload_create['googleSelected'] = True
                    key = 'google'
                
                if 'azure' in template_details['config']:
                    payload_create['azureSelected'] = True
                    key = 'azure'

                if 'openstack' in template_details['config']:
                    payload_create['openstackSelected'] = True
                    key = 'openstack'

                if 'openstack' in template_details['config']:
                    payload_create['openstackSelected'] = True
                    key = 'openstack'

                data = template_details['config'][key]
                payload_create[key] = {}
                payload_create[key]['account'] = data['account']
                # print("----- ACCOUNT: ", payload_create[key]['account'], "\n")
                payload_create[key]['region'] = data['region']
                payload_create[key]['nodes'] = data['nodes']
                payload_create[key]['vpcCidr'] = data['vpcCidr']
                
                # print("Creation template: ", json.dumps(payload_create))
                r3 = session.post(url+"/server/createKubernetesCluster",data = json.dumps(payload_create), headers={"content-type":"application/json"})
                if r3.status_code == 200:
                    print("cluster creation started")
                    created_cluster_ids.append(json.loads(r3.text)["ID"])
                    # break # create just the first template
                elif r3.status_code == 400 and r3.text == '{"error": {"message": "Environment with that name already exists."}}':
                    print("Env already exists")
                else:
                    print("----- Error creating from template: ", template['name'], "Endpoint: /server/createKubernetesCluster", "payload", json.dumps(payload_create), "\n")
                    print("status_code: ", r3.status_code, "response: ", r3.text)
                    return False, created_cluster_ids

                # break
    else:
        print("Error: cannot get templates, exiting.")
        print("status_code: ", r.status_code, "response: ", r.text)
        return False, created_cluster_ids


    #### wait for resources to finish
    sleepIntervalSeconds = 20
    counter = 0
    timeoutSeconds = 60 * 60 * 3 # 2 h
    print("Waiting for tests to finish, TIMEOUT=", timeoutSeconds)
    all_success = True
    all_fail = True
    while True:
        #TODO: check cluster["installstep"] == 0 for successfull install
        all_success = True
        all_fail = True
        r = session.post(url+"/server/getClusterList", data = {}, headers={"content-type":"application/json"})
        if r.status_code == 200:
            clusterlist = json.loads(r.text)
            for cluster in clusterlist:
                # print("installstep", cluster["installstep"])
                if cluster["installstep"] > 0: # this cluster is creating and has not failed
                    all_fail = False
                    all_success = False
                if cluster["installstep"] < 0: # this cluster has failed
                    all_success = False
                    # print error
                    print("status_code: ", r.status_code, "response: ", r.text)
        if all_success:
            print("")
            print("All resources are created successfully")
            break;
        if all_fail:
            print("All resources have failed to create")
            break;
        print(".", end = '', flush=True)
        counter += sleepIntervalSeconds
        if counter > timeoutSeconds:
            print("Timeout elapsed, " + str(timeoutSeconds))
            break
        time.sleep(sleepIntervalSeconds)
    return all_success, created_cluster_ids

def getEndStatus(session, url, cluster_ids):
    # get detailed errrors (if any)
    time.sleep(10)
    r = session.post(url+"/server/getClusterList", data = {}, headers={"content-type":"application/json"})
    if r.status_code == 200:
        # get status for every cluster
        clusterlist = json.loads(r.text)
        for cluster in clusterlist:
            if cluster["installstep"] != 0:
                if cluster["id"] in cluster_ids:
                    r3 = session.post(url+"/server/getInstallationStatus", data = json.dumps({ "ID" : cluster["id"] }), headers={"content-type":"application/json"})
                    if r3.status_code == 200:
                        print("cluster.name", cluster["name"], "\n", r3.text)
                    else:
                        print("status_code: ", r3.status_code, "response: ", r3.text)
        r = session.post(url+"/server/getClusterList", data = {}, headers={"content-type":"application/json"})
        clusterlist = json.loads(r.text)
    else:
        print("Error getting cluster list", "HTTP status code", r.status_code, "Response", r.text)
        return False
    return True

def deleteResources(session, url, cluster_ids):
    # delete all created resources
    print("")
    print("Deleting all created clusters")
    print("len(cluster_ids): ", len(cluster_ids))
    r = session.post(url+"/server/getClusterList", data = {}, headers={"content-type":"application/json"})
    all_success = True
    if r.status_code == 200:
        # get status for every cluster
        clusterlist = json.loads(r.text)
        while len(cluster_ids) > 0:
            for cluster in clusterlist:
                print("Trying to delete cluster ...")
                if cluster["id"] in cluster_ids:
                    print("-------- deleting cluster id", cluster["id"], "\n")
                    if cluster["installstep"] != 100: # skip clusters which are currently being deleted
                        print("Deleting cluster", "ID", cluster["id"], "install step: ", cluster["installstep"])
                        delete_payload = {"clusterID": cluster["id"]}
                        r3 = session.post(url+"/server/deleteCluster", data = json.dumps(delete_payload), headers={"content-type":"application/json"})
                        if r3.status_code != 200:
                            all_success = False
                            print("ERROR deleting cluster, status_code: ", r3.status_code, "response: ", r3.text)
                        else:
                            newlist = []
                            for id in cluster_ids:
                                if id != cluster["id"]:
                                    newlist.append(id)
                            cluster_ids = newlist
    else:
        print("Error getting cluster list")
        all_success = False

    return all_success


