#!/usr/bin/env bash
for i in {50..60}
do
    for j in {1..250}
    do
      cat << EOF
---
apiVersion: v1
kind: Node
metadata:
  name: n$i-$j
  annotations:
    flannel.alpha.coreos.com/backend-data: ""
    flannel.alpha.coreos.com/backend-type: host-gw
    flannel.alpha.coreos.com/kube-subnet-manager: "true"
    flannel.alpha.coreos.com/public-ip: 172.17.$i.$j
spec:
  podCIDR: 10.$i.$j.0/24
EOF

    done
done