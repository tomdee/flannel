#!/usr/bin/env bash
for i in {50..60}
do
    for j in {1..250}
    do
    echo $i $j
#      etcdctl set /coreos.com/network/subnets/10.$i.$j.0-24 '{"PublicIP":"172.17.'$i'.'$j'","BackendType":"host-gw"}'
      etcdctl set /vxlan/network/subnets/10.$i.$j.0-24 '{"PublicIP":"172.17.'$i'.'$j'","BackendType":"vxlan","BackendData":{"VtepMAC":"ee:ee:ee:ee:'`printf '%x\n' $i`':'`printf '%02x\n' $j`'"}}'
    done
done

#docker run --rm --net=host quay.io/coreos/etcd etcdctl set /vxlan/network/config '{ "Network": "10.0.0.0/8", "Backend": {"Type": "vxlan"}}'