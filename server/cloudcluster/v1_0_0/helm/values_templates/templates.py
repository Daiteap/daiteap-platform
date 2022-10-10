basic_template = '''{
affinity: 
{
        nodeAffinity:
        {
                requiredDuringSchedulingIgnoredDuringExecution: 
                {
                        nodeSelectorTerms:
                        [                                
                                matchExpressions: 
                                [
                                        {
                                                key: provider,
                                                operator: In,
                                                values:
                                                [
                                                        $providers
                                                ]
                                        }
                                ]
                        ]
                }
        }
},
service: 
{
        type: $service_type
}
}'''

basic_template_with_replicas = '''{
affinity: 
{
        nodeAffinity:
        {
                requiredDuringSchedulingIgnoredDuringExecution: 
                {
                        nodeSelectorTerms:
                        [                                
                                matchExpressions: 
                                [
                                        {
                                                key: provider,
                                                operator: In,
                                                values:
                                                [
                                                        $providers
                                                ]
                                        }
                                ]
                        ]
                }
        }
},
service: 
{
        type: $service_type
},
replicaCount: $replicas
}'''

elasticsearch_template = '''
---
replicas: $replicas 
minimumMasterNodes: $minimum_master_nodes

resources:
  requests:
    cpu: $requests_cpu
    memory: $requests_memory
  limits:
    cpu: "1000m"
    memory: "2Gi"

volumeClaimTemplate:
  accessModes: [ "ReadWriteOnce" ]
  storageClassName: $storage_class
  resources:
    requests:
      storage: 30Gi

antiAffinity: "soft"
'''

kibana_template = '''
---
resources:
  requests:
    cpu: $requests_cpu
    memory: $requests_memory
  limits:
    cpu: "1000m"
    memory: "2Gi"

extraEnvs:
  - name: "NODE_OPTIONS"
    value: "--max-old-space-size=1800"
  - name: 'ELASTICSEARCH_USERNAME'
    valueFrom:
      secretKeyRef:
        name: elastic-credentials
        key: username
  - name: 'ELASTICSEARCH_PASSWORD'
    valueFrom:
      secretKeyRef:
        name: elastic-credentials
        key: password
  - name: 'KIBANA_ENCRYPTION_KEY'
    value: "$kibana_encryption_key"

service:
  type: NodePort
  loadBalancerIP: ""
  port: 5601
  nodePort: $node_port
  labels: {}
  annotations: {}
  httpPortName: service
'''

logstash_template = '''{
}'''

fluentd_template = '''
---
elasticsearch:
  auth:
    enabled: true
    user: "elastic"
    password: "$elastic_password"
'''

istio_base_template = '''
---
global:
  istioNamespace: "$istio_namespace"
'''

mysql_template = '''{
  configurationFiles: {
    mysql.cnf: "[mysqld]\nbind-address = 0.0.0.0\n"
  },
  affinity: 
  {
          nodeAffinity:
          {
                  requiredDuringSchedulingIgnoredDuringExecution: 
                  {
                          nodeSelectorTerms:
                          [                                
                                  matchExpressions: 
                                  [
                                          {
                                                  key: provider,
                                                  operator: In,
                                                  values:
                                                  [
                                                          $providers
                                                  ]
                                          }
                                  ]
                          ]
                  }
          }
  },
  service: 
  {
          type: $service_type
  }
  }'''
  
mysql_template_with_replicas = '''{
    configurationFiles: {
      mysql.cnf: "[mysqld]\nbind-address = 0.0.0.0\n"
    },
  affinity: 
  {
          nodeAffinity:
          {
                  requiredDuringSchedulingIgnoredDuringExecution: 
                  {
                          nodeSelectorTerms:
                          [                                
                                  matchExpressions: 
                                  [
                                          {
                                                  key: provider,
                                                  operator: In,
                                                  values:
                                                  [
                                                          $providers
                                                  ]
                                          }
                                  ]
                          ]
                  }
          }
  },
  service: 
  {
          type: $service_type
  },
  replicaCount: $replicas
  }'''