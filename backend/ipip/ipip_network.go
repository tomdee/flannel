// Copyright 2017 flannel authors
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
	"bytes"
	"net"
	"sync"
	"time"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	log "github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
)

const (
	routeCheckRetries = 10
)

type network struct {
	backend.SimpleNetwork
	backendType string
	routes      []netlink.Route
	sm          subnet.Manager
	dev         *tunnelDev
}

func (n *network) MTU() int {
	return n.dev.iptun.Attrs().MTU
}

func (n *network) Run(ctx context.Context) {
	wg := sync.WaitGroup{}

	log.Info("Watching for new subnet leases")
	evts := make(chan []subnet.Event)
	wg.Add(1)
	go func() {
		subnet.WatchLeases(ctx, n.sm, n.SubnetLease, evts)
		wg.Done()
	}()

	n.routes = make([]netlink.Route, 0, 10)
	wg.Add(1)
	go func() {
		n.routeCheck(ctx)
		wg.Done()
	}()

	defer wg.Wait()

	for {
		select {
		case evtBatch := <-evts:
			n.handleSubnetEvents(evtBatch)

		case <-ctx.Done():
			return
		}
	}
}

func (n *network) handleSubnetEvents(batch []subnet.Event) {
	for _, evt := range batch {
		switch evt.Type {
		case subnet.EventAdded:
			log.Infof("Subnet added: %v via %v", evt.Lease.Subnet, evt.Lease.Attrs.PublicIP)

			if evt.Lease.Attrs.BackendType != n.backendType {
				log.Warningf("Ignoring non-%v subnet: type=%v", n.backendType, evt.Lease.Attrs.BackendType)
				continue
			}
			route := n.getRoute(&evt.Lease)

			n.addToRouteList(*route)
			// Check if route exists before attempting to add it
			routeList, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Dst: route.Dst}, netlink.RT_FILTER_DST)
			if err != nil {
				log.Warningf("Unable to list routes: %v", err)
			}
			if len(routeList) > 0 && (!routeList[0].Gw.Equal(route.Gw) || routeList[0].LinkIndex != route.LinkIndex) {
				// Same Dst different Gw or different link index. Remove it, correct route will be added below.
				log.Warningf("Replacing existing route to %v via %v dev index %d with %v via %v dev index %d.", evt.Lease.Subnet, routeList[0].Gw, routeList[0].LinkIndex, evt.Lease.Subnet, evt.Lease.Attrs.PublicIP, route.LinkIndex)
				if err := netlink.RouteDel(&routeList[0]); err != nil {
					log.Errorf("Error deleting route to %v: %v", evt.Lease.Subnet, err)
					continue
				}
				n.removeFromRouteList(routeList[0])
			}
			if len(routeList) > 0 && routeList[0].Gw.Equal(route.Gw) && routeList[0].LinkIndex == route.LinkIndex {
				// Same Dst and same Gw, keep it and do not attempt to add it.
				log.Infof("Route to %v via %v dev index %d already exists, skipping.", evt.Lease.Subnet, evt.Lease.Attrs.PublicIP, routeList[0].LinkIndex)
			} else if err := netlink.RouteAdd(route); err != nil {
				log.Errorf("Error adding route to %v via %v dev index %d: %v", evt.Lease.Subnet, evt.Lease.Attrs.PublicIP, route.LinkIndex, err)
				continue
			}

		case subnet.EventRemoved:
			log.Info("Subnet removed: ", evt.Lease.Subnet)

			if evt.Lease.Attrs.BackendType != n.backendType {
				log.Warningf("Ignoring non-%v subnet: type=%v", n.backendType, evt.Lease.Attrs.BackendType)
				continue
			}

			route := n.getRoute(&evt.Lease)
			if err := netlink.RouteDel(route); err != nil {
				log.Errorf("Error deleting route to %v: %v", evt.Lease.Subnet, err)
				continue
			}
			n.removeFromRouteList(*route)

		default:
			log.Error("Internal error: unknown event type: ", int(evt.Type))
		}
	}
}

func (n *network) addToRouteList(route netlink.Route) {
	for _, r := range n.routes {
		if routeEqual(r, route) {
			return
		}
	}
	n.routes = append(n.routes, route)
}

func (n *network) removeFromRouteList(route netlink.Route) {
	for index, r := range n.routes {
		if routeEqual(r, route) {
			n.routes = append(n.routes[:index], n.routes[index+1:]...)
			return
		}
	}
}

func (n *network) routeCheck(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(routeCheckRetries * time.Second):
			n.checkSubnetExistInRoutes()
		}
	}
}

func (n *network) checkSubnetExistInRoutes() {
	routeList, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err == nil {
		for _, route := range n.routes {
			exist := false
			for _, r := range routeList {
				if r.Dst == nil {
					continue
				}
				if routeEqual(r, route) {
					exist = true
					break
				}
			}
			if !exist {
				if err := netlink.RouteAdd(&route); err != nil {
					if nerr, ok := err.(net.Error); !ok {
						log.Errorf("Error recovering route to %v: %v, %v", route.Dst, route.Gw, nerr)
					}
					continue
				} else {
					log.Infof("Route recovered %v : %v", route.Dst, route.Gw)
				}
			}
		}
	}
}

func routeEqual(x, y netlink.Route) bool {
	if x.Dst.IP.Equal(y.Dst.IP) && x.Gw.Equal(y.Gw) && bytes.Equal(x.Dst.Mask, y.Dst.Mask) && x.LinkIndex == y.LinkIndex {
		return true
	}
	return false
}

func (n *network) getRoute(lease *subnet.Lease) *netlink.Route {
	route := netlink.Route{
		Dst:       lease.Subnet.ToIPNet(),
		Gw:        lease.Attrs.PublicIP.ToIP(),
		LinkIndex: n.dev.iptun.Attrs().Index,
		Flags:     int(netlink.FLAG_ONLINK),
	}
	if n.dev.directRouting {
		dr, err := ip.DirectRouting(lease.Attrs.PublicIP.ToIP())
		if err != nil {
			log.Error(err)
		}
		if dr {
			log.V(2).Infof("configure route to %v via direct routing", lease.Attrs.PublicIP.String())
			route.LinkIndex = n.ExtIface.Iface.Index
		}
	}
	return &route
}
