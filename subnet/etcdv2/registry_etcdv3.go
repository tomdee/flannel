// Copyright 2015 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// TODO - wrong package. Kinda tricky to split this all out since it shares a lot with etcdv2
package etcdv2

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sync"
	"time"

	etcd "github.com/coreos/etcd/clientv3"
	log "github.com/golang/glog"
	"golang.org/x/net/context"

	"github.com/coreos/flannel/pkg/ip"
	. "github.com/coreos/flannel/subnet"
)

type etcdV3NewFunc func(c *EtcdConfig) (*etcd.Client, error)

type etcdV3SubnetRegistry struct {
	cliNewFunc   etcdV3NewFunc
	mux          sync.Mutex
	cli          *etcd.Client
	etcdCfg      *EtcdConfig
	networkRegex *regexp.Regexp
}

func newEtcdV3Client(c *EtcdConfig) (*etcd.Client, error) {

	cli, err := etcd.New(etcd.Config{
		// TODO - confid of etcd
		Endpoints:   c.Endpoints,
		DialTimeout: 5 * time.Second,
	})

	// TODO - here are notes on TLS
	//tlsInfo := transport.TLSInfo{
	//CertFile: c.Certfile,
	//KeyFile:  c.Keyfile,
	//CAFile:   c.CAFile,
	//}

	//t, err := transport.NewTransport(tlsInfo, time.Second)
	//if err != nil {
	//return nil, err
	//}

	//cli, err := etcd.New(etcd.Config{
	//Endpoints: c.Endpoints,
	//Transport: t,
	//Username:  c.Username,
	//Password:  c.Password,
	//})
	if err != nil {
		return nil, err
	}

	log.Info("Created etcd v3 client")

	return cli, nil
}

func newEtcdV3SubnetRegistry(config *EtcdConfig, cliNewFunc etcdV3NewFunc) (Registry, error) {
	r := &etcdV3SubnetRegistry{
		etcdCfg:      config,
		networkRegex: regexp.MustCompile(config.Prefix + `/([^/]*)(/|/config)?$`),
	}
	if cliNewFunc != nil {
		r.cliNewFunc = cliNewFunc
	} else {
		r.cliNewFunc = newEtcdV3Client
	}

	var err error
	r.cli, err = r.cliNewFunc(config)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (esr *etcdV3SubnetRegistry) getNetworkConfig(ctx context.Context) (string, error) {
	log.V(5).Info("Getting network config")
	key := path.Join(esr.etcdCfg.Prefix, "config")
	resp, err := esr.cli.Get(ctx, key)

	if err != nil {
		return "", err
	}

	if len(resp.Kvs) == 0 {
		return "", fmt.Errorf("Network not found at path: %s", key)
	}
	return string(resp.Kvs[0].Value), nil
}

// getSubnets queries etcd to get a list of currently allocated leases for a given network.
// It returns the leases along with the "as-of" etcd-index that can be used as the starting
// point for etcd watch.
func (esr *etcdV3SubnetRegistry) getSubnets(ctx context.Context) ([]Lease, uint64, error) {
	log.V(5).Info("Getting subnets config")
	key := path.Join(esr.etcdCfg.Prefix, "subnets")
	resp, err := esr.cli.Get(ctx, key)

	if err != nil {
		return nil, 0, err
	}

	if len(resp.Kvs) == 0 {
		// key not found: treat it as empty set
		return []Lease{}, uint64(resp.Header.Revision), nil
	}

	leases := []Lease{}
	for _, kvs := range resp.Kvs {
		l, err := nodeToLeasev3(string(kvs.Key), kvs.Value, uint64(kvs.ModRevision))
		if err != nil {
			log.Warningf("Ignoring bad subnet node: %v", err)
			continue
		}

		leases = append(leases, *l)
	}

	return leases, uint64(resp.Header.Revision), nil
}

func (esr *etcdV3SubnetRegistry) getSubnet(ctx context.Context, sn ip.IP4Net) (*Lease, uint64, error) {
	log.V(5).Infof("Getting subnet: %s", sn)
	key := path.Join(esr.etcdCfg.Prefix, "subnets", MakeSubnetKey(sn))
	resp, err := esr.cli.Get(ctx, key)

	if err != nil {
		return nil, 0, err
	}
	l, err := nodeToLeasev3(string(resp.Kvs[0].Key), resp.Kvs[0].Value, uint64(resp.Kvs[0].ModRevision))
	return l, uint64(resp.Header.Revision), err
}

func nodeToLeasev3(key string, value []byte, revision uint64) (*Lease, error) {
	sn := ParseSubnetKey(key)
	if sn == nil {
		return nil, fmt.Errorf("failed to parse subnet key %s", key)
	}

	attrs := &LeaseAttrs{}
	if err := json.Unmarshal([]byte(value), attrs); err != nil {
		return nil, err
	}

	exp := time.Time{}
	//if node.Expiration != nil {
	//	exp = *node.Expiration
	//}

	lease := Lease{
		Subnet:     *sn,
		Attrs:      *attrs,
		Expiration: exp,
		Asof:       revision,
	}

	return &lease, nil
}

func (esr *etcdV3SubnetRegistry) createSubnet(ctx context.Context, sn ip.IP4Net, attrs *LeaseAttrs, ttl time.Duration) (time.Time, error) {
	log.V(5).Infof("Creating subnet (%s) with attrs %s and ttl %s", sn, attrs, ttl)
	key := path.Join(esr.etcdCfg.Prefix, "subnets", MakeSubnetKey(sn))
	value, err := json.Marshal(attrs)
	if err != nil {
		return time.Time{}, err
	}

	// Only create if needed
	_, err = esr.cli.Txn(ctx).
		If(etcd.Compare(etcd.Version(key), "=", 0)).
		Then(etcd.OpPut(key, string(value))).
		Commit()

	if err != nil {
		return time.Time{}, err
	}

	return time.Now().Add(ttl), nil
}

func (esr *etcdV3SubnetRegistry) updateSubnet(ctx context.Context, sn ip.IP4Net, attrs *LeaseAttrs, ttl time.Duration, asof uint64) (time.Time, error) {
	panic("")
	return time.Time{}, nil
}

func (esr *etcdV3SubnetRegistry) deleteSubnet(ctx context.Context, sn ip.IP4Net) error {
	panic("")
	return nil
}

func (esr *etcdV3SubnetRegistry) watchSubnets(ctx context.Context, since uint64) (Event, uint64, error) {
	log.V(5).Infof("Watching subnets since %d", since)
	key := path.Join(esr.etcdCfg.Prefix, "subnets")
	// TODO - not sure about the watchprefix stuff
	since++
	rch := esr.cli.Watch(ctx, key, etcd.WithPrefix(), etcd.WithRev(int64(since)))
	for wresp := range rch {
		if wresp.Canceled {
			return Event{}, 0, wresp.Err()
		}
		for _, ev := range wresp.Events {

			fmt.Printf("SUBNETS: %s %q : %q\n", ev.Type, ev.Kv.Key, ev.Kv.Value)
			evt, err := parseSubnetWatchResponseV3(ev)
			return evt, uint64(ev.Kv.ModRevision), err
		}
	}
	return Event{}, 0, nil
}

func (esr *etcdV3SubnetRegistry) watchSubnet(ctx context.Context, since uint64, sn ip.IP4Net) (Event, uint64, error) {
	log.V(5).Infof("Watching subnet (%s) since %d", sn, since)
	since++
	key := path.Join(esr.etcdCfg.Prefix, "subnets", MakeSubnetKey(sn))
	rch := esr.cli.Watch(context.Background(), key, etcd.WithRev(int64(since)))
	for wresp := range rch {
		if wresp.Canceled {
			return Event{}, 0, wresp.Err()
		}
		for _, ev := range wresp.Events {

			fmt.Printf("SUBNET: %s %q : %q\n", ev.Type, ev.Kv.Key, ev.Kv.Value)
			evt, err := parseSubnetWatchResponseV3(ev)
			return evt, uint64(ev.Kv.ModRevision), err
		}
	}
	return Event{}, 0, nil
}

func parseSubnetWatchResponseV3(resp *etcd.Event) (Event, error) {
	sn := ParseSubnetKey(string(resp.Kv.Key))
	if sn == nil {
		return Event{}, fmt.Errorf("%v %q: not a subnet, skipping", resp, resp.Kv.Key)
	}

	switch resp.Type {

	//TODO
	//case "delete", "expire":
	//return Event{
	//EventRemoved,
	//Lease{Subnet: *sn},
	//"",
	//}, nil

	default:
		attrs := &LeaseAttrs{}
		err := json.Unmarshal(resp.Kv.Value, attrs)
		if err != nil {
			return Event{}, err
		}

		exp := time.Time{}
		//if resp.Node.Expiration != nil {
		//exp = *resp.Node.Expiration
		//}

		evt := Event{
			EventAdded,
			Lease{
				Subnet:     *sn,
				Attrs:      *attrs,
				Expiration: exp,
			},
		}
		return evt, nil
	}
}
