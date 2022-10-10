import yaml

def build_inventory(nodes, location='ansible/playbooks/kubespray/inventory/sample/inventory.yaml'):
    inventory = {
        "all": {
            "hosts": {
            },
            "children": {
                "kube-master": {
                    "hosts": {
                    }
                },
                "kube-node": {
                    "hosts": {
                    }
                },
                "etcd": {
                    "hosts": {
                    }
                },
                "k8s-cluster": {
                    "children": {
                        "kube-master": None,
                        "kube-node": None
                    }
                },
                "calico-rr": {
                    "hosts": {}
                }
            }
        }
    }

    for node in nodes:
        inventory['all']['hosts'][node['id']] = {
            "ansible_host": node['address'],
            "ip": node['address'],
            "access_ip": node['address']
        }
        inventory['all']['children']['kube-node']['hosts'][node['id']] = None

        if 'kube_master' in node and node['kube_master']:
            inventory['all']['children']['kube-master']['hosts'][node['id']] = None

        if 'kube_etcd' in node and node['kube_etcd']:
            inventory['all']['children']['etcd']['hosts'][node['id']] = None

    with open(location, 'w') as f:
        yaml.dump(inventory, f)

def add_kubernetes_roles_to_nodes(resources, nodes):
    for provider in nodes:
        for i in range(len(nodes[provider])):
            if resources[provider]['nodes'][i]['is_control_plane']:
                nodes[provider][i]['kube_master'] = True
                nodes[provider][i]['kube_etcd'] = True
            else:
                nodes[provider][i]['kube_master'] = False
                nodes[provider][i]['kube_etcd'] = False

    return nodes

def add_kubernetes_roles_to_tfstate_resources(resources, tfstate_resources):
    for provider in tfstate_resources:
        for clouds_node in tfstate_resources[provider]:
            for resources_node in resources[provider]['nodes']:
                if resources_node['name'] == clouds_node['name']:
                    if resources_node['is_control_plane']:
                        clouds_node['kube_master'] = True
                        clouds_node['kube_etcd'] = True
                    else:
                        clouds_node['kube_master'] = False
                        clouds_node['kube_etcd'] = False
                    break

    return tfstate_resources

def add_roles_to_k3s_nodes(nodes):
    for provider in nodes:
        if len(nodes[provider]):
            nodes[provider][0]['kube_master'] = 1
            break

    return nodes