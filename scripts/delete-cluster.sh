#!/bin/bash

echo --- Delete Namespace Daiteap ---

kubectl delete namespace daiteap --timeout=5m

echo --- Delete Cluster ---

kind delete cluster
