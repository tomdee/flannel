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

package ipip

import (
	"encoding/json"
	"fmt"
	"net"
	"syscall"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	glog "github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
)

const (
	backendType  = "ipip"
	tunnelName   = "tunl0"
	tunnelMaxMTU = 1480
)

func init() {
	backend.Register(backendType, New)
}

type IPIPBackend struct {
	sm       subnet.Manager
	extIface *backend.ExternalInterface
}

func New(sm subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	if !extIface.ExtAddr.Equal(extIface.IfaceAddr) {
		return nil, fmt.Errorf("your PublicIP differs from interface IP, meaning that probably you're on a NAT, which is not supported by ipip backend")
	}

	be := &IPIPBackend{
		sm:       sm,
		extIface: extIface,
	}
	return be, nil
}

func (be *IPIPBackend) RegisterNetwork(ctx context.Context, config *subnet.Config) (backend.Network, error) {
	cfg := struct {
		DirectRouting bool
	}{}
	if len(config.Backend) > 0 {
		if err := json.Unmarshal(config.Backend, &cfg); err != nil {
			return nil, fmt.Errorf("error decoding IPIP backend config: %v", err)
		}
	}
	glog.Infof("IPIP config: DirectRouting=%v", cfg.DirectRouting)

	n := &network{
		SimpleNetwork: backend.SimpleNetwork{
			ExtIface: be.extIface,
		},
		sm:          be.sm,
		backendType: backendType,
	}

	attrs := &subnet.LeaseAttrs{
		PublicIP:    ip.FromIP(be.extIface.ExtAddr),
		BackendType: backendType,
	}

	l, err := be.sm.AcquireLease(ctx, attrs)
	switch err {
	case nil:
		n.SubnetLease = l
	case context.Canceled, context.DeadlineExceeded:
		return nil, err
	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}
	dev, err := configureIPIPDevice(n.SubnetLease, config.Network)
	if err != nil {
		return nil, err
	}
	dev.directRouting = cfg.DirectRouting
	n.dev = dev

	return n, nil
}

func configureIPIPDevice(lease *subnet.Lease, ipNet ip.IP4Net) (*tunnelDev, error) {
	link, err := netlink.LinkByName(tunnelName)
	if err != nil {
		if err == syscall.EEXIST {
			link = &netlink.Iptun{LinkAttrs: netlink.LinkAttrs{Name: tunnelName}}
			if err := netlink.LinkAdd(link); err != nil {
				return nil, fmt.Errorf("failed to create tunnel %v: %v", tunnelName, err)
			}
		} else {
			return nil, err
		}
	}
	if link.Type() != "ipip" {
		return nil, fmt.Errorf("%v not in ipip mode", tunnelName)
	}
	ipip, ok := link.(*netlink.Iptun)
	if !ok {
		return nil, fmt.Errorf("failed to convert to iptun link")
	}
	if (ipip.Local != nil && ipip.Local.String() != "0.0.0.0") || (ipip.Remote != nil && ipip.Remote.String() != "0.0.0.0") {
		return nil, fmt.Errorf("local %v or remote %v of tunnel %s is not expected", ipip.Local, ipip.Remote, tunnelName)
	}
	oldMTU := link.Attrs().MTU
	if oldMTU > tunnelMaxMTU {
		glog.Infof("%s MTU(%d) greater than %d, setting it to %d", tunnelName, oldMTU, tunnelMaxMTU, tunnelMaxMTU)
		err := netlink.LinkSetMTU(link, tunnelMaxMTU)
		if err != nil {
			return nil, fmt.Errorf("failed to set %v MTU to %v: %v", tunnelName, tunnelMaxMTU, err)
		}
	} else if oldMTU == 0 {
		glog.Infof("%v MTU is 0, setting it to %v", tunnelName, tunnelMaxMTU)
		err := netlink.LinkSetMTU(link, tunnelMaxMTU)
		if err != nil {
			return nil, fmt.Errorf("failed to set %v MTU to %v: %v", tunnelName, tunnelMaxMTU, err)
		}
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		err := netlink.LinkSetUp(link)
		if err != nil {
			return nil, fmt.Errorf("failed to set %v UP: %v", tunnelName, err)
		}
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("failed to list addr for dev %v: %v", tunnelName, err)
	}
	newAddr := lease.Subnet.Network().IP.ToIP()
	found := false
	for _, oldAddr := range addrs {
		if oldAddr.IP.Equal(newAddr) {
			found = true
			continue
		}
		if ipNet.Contains(ip.FromIP(oldAddr.IP)) {
			glog.Infof("deleting old addr %s from %s", oldAddr.IP.String(), tunnelName)
			if err := netlink.AddrDel(link, &oldAddr); err != nil {
				return nil, fmt.Errorf("failed to remove old addr %s from %s: %v", oldAddr.IP.String(), tunnelName, err)
			}
		}
	}
	if !found {
		mask := net.CIDRMask(32, 32)
		ipNet := net.IPNet{
			IP:   newAddr.Mask(mask),
			Mask: mask,
		}
		addr := &netlink.Addr{
			IPNet: &ipNet,
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return nil, fmt.Errorf("failed to add addr %s to %s: %v", addr.IP.String(), tunnelName, err)
		}
	}
	return &tunnelDev{iptun: link.(*netlink.Iptun)}, nil
}

type tunnelDev struct {
	iptun         *netlink.Iptun
	directRouting bool
}
