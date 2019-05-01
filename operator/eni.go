// Copyright 2019 Authors of Cilium
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

package main

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	lyftaws "github.com/lyft/cni-ipvlan-vpc-k8s/aws"
	"github.com/lyft/cni-ipvlan-vpc-k8s/aws/cache"
)

const (
	defaultPreAllocation = 4
)

var (
	awsSession       *session.Session
	ec2Client        ec2iface.EC2API
	metadataClient   *ec2metadata.EC2Metadata
	identityDocument *ec2metadata.EC2InstanceIdentityDocument
)

type subnet struct {
	ID                    string
	Cidr                  string
	IsDefault             bool
	AvailableAddressCount int
	Name                  string
	Tags                  map[string]string
}

func getCachedSubnets() (subnets []subnet, err error) {
	state := cache.Get("subnets_for_instance", &subnets)
	if state == cache.CacheFound {
		return
	}
	subnets, err = getSubnets()
	if err == nil {
		cache.Store("subnets", time.Minute, &subnets)
	}
	return
}

func newEc2Filter(name string, values ...string) *ec2.Filter {
	filter := &ec2.Filter{
		Name: aws.String(name),
	}
	for _, value := range values {
		filter.Values = append(filter.Values, aws.String(value))
	}
	return filter
}

func getSubnets() ([]subnet, error) {
	var subnets []subnet

	az := identityDocument.AvailabilityZone

	// getting all interfaces attached to this specific machine so we can
	// find out what is our vpc-id interfaces[0] is going to be our eth0,
	// interfaces slice gets sorted by number before returning to the
	// caller
	interfaces, err := getInterfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %s", err)
	}

	result, err := ec2Client.DescribeSubnets(&ec2.DescribeSubnetsInput{
		Filters: []*ec2.Filter{
			newEc2Filter("vpc-id", interfaces[0].VPC.ID),
			newEc2Filter("availabilityZone", az),
		},
	})

	if err != nil {
		return nil, err
	}

	for _, awsSub := range result.Subnets {
		subnet := subnet{
			ID:                    *awsSub.SubnetId,
			Cidr:                  *awsSub.CidrBlock,
			IsDefault:             *awsSub.DefaultForAz,
			AvailableAddressCount: int(*awsSub.AvailableIpAddressCount),
			Tags:                  map[string]string{},
		}
		// Set all the tags on the result
		for _, tag := range awsSub.Tags {
			if *tag.Key == "Name" {
				subnet.Name = *tag.Value
			} else {
				subnet.Tags[*tag.Key] = *tag.Value
			}
		}
		subnets = append(subnets, subnet)
	}

	return subnets, nil
}

func convertToENI(iface *ec2.NetworkInterface) (v2.ENI, error) {
	if iface.PrivateIpAddress == nil {
		return v2.ENI{}, fmt.Errorf("ENI has no IP address")
	}

	eni := v2.ENI{
		IP:             *iface.PrivateIpAddress,
		SecurityGroups: []string{},
		Addresses:      []string{},
	}

	if iface.MacAddress != nil {
		eni.MAC = *iface.MacAddress
	}

	if iface.NetworkInterfaceId != nil {
		eni.ID = *iface.NetworkInterfaceId
	}

	if iface.Description != nil {
		eni.Description = *iface.Description
	}

	if iface.Attachment != nil {
		if iface.Attachment.DeviceIndex != nil {
			eni.Number = int(*iface.Attachment.DeviceIndex)
		}

		if iface.Attachment.InstanceId != nil {
			eni.InstanceID = *iface.Attachment.InstanceId
		}
	}

	if iface.SubnetId != nil {
		eni.Subnet.ID = *iface.SubnetId
	}

	if iface.VpcId != nil {
		eni.VPC.ID = *iface.VpcId
	}

	for _, ip := range iface.PrivateIpAddresses {
		if ip.PrivateIpAddress != nil {
			eni.Addresses = append(eni.Addresses, *ip.PrivateIpAddress)
		}
	}

	//	for _, ip := range iface.Ipv6Addresses {
	//		if ip.Ipv6Address {
	//			eni.Addresses = append(eni.Addresses, *ip.Ipv6Address)
	//		}
	//	}

	for _, g := range iface.Groups {
		if g.GroupId != nil {
			eni.SecurityGroups = append(eni.SecurityGroups, *g.GroupId)
		}
	}

	return eni, nil
}

func getInterfaces() ([]v2.ENI, error) {
	var interfaces []v2.ENI

	req := ec2.DescribeNetworkInterfacesInput{}
	response, err := ec2Client.DescribeNetworkInterfaces(&req)
	if err != nil {
		return nil, err
	}

	for _, iface := range response.NetworkInterfaces {
		eni, err := convertToENI(iface)
		if err != nil {
			return nil, err
		}
		interfaces = append(interfaces, eni)
	}

	//	macResult, err := metadataClient.GetMetadata("network/interfaces/macs/")
	//	if err != nil {
	//		return nil, err
	//	}
	//
	//	macs := strings.Split(macResult, "\n")
	//	for _, mac := range macs {
	//		if len(mac) < 1 {
	//			continue
	//		}
	//		mac = mac[:len(mac)-1]
	//		iface, err := getInterface(mac)
	//		if err != nil {
	//			return nil, err
	//		}
	//		interfaces = append(interfaces, iface)
	//	}

	// TODO: sort

	return interfaces, nil
}

func allocate(node *v2.CiliumNode) error {
	//	var alloc *aws.AllocationResult
	//	registry := &aws.Registry{}
	//	free, err := aws.FindFreeIPsAtIndex(node.Spec.ENI.FirstAllocationInterface, true)
	//	if err == nil && len(free) > 0 {
	//		registryFreeIPs, err := registry.TrackedBefore(time.Now().Add(time.Duration(-3600) * time.Second))
	//		if err == nil && len(registryFreeIPs) > 0 {
	//		loop:
	//			for _, freeAlloc := range free {
	//				for _, freeRegistry := range registryFreeIPs {
	//					if freeAlloc.IP.Equal(freeRegistry) {
	//						alloc = freeAlloc
	//						// update timestamp
	//						registry.TrackIP(freeRegistry)
	//						break loop
	//					}
	//				}
	//			}
	//		}
	//	}
	//
	//	// No free IPs available for use, so let's allocate one
	//	if alloc == nil {
	//		// allocate an IP on an available interface
	//		alloc, err = aws.DefaultClient.AllocateIPFirstAvailableAtIndex(node.Spec.ENI.FirstAllocationInterface)
	//		if err != nil {
	//			// failed, so attempt to add an IP to a new interface
	//			newIf, err := aws.DefaultClient.NewInterface(node.Spec.ENI.SecurityGroups, node.Spec.ENI.SubnetTags)
	//			// If this interface has somehow gained more than one IP since being allocated,
	//			// abort this process and let a subsequent run find a valid IP.
	//			if err != nil || len(newIf.IPv4s) != 1 {
	//				return fmt.Errorf("unable to create a new elastic network interface due to %v",
	//					err)
	//			}
	//			// Freshly allocated interfaces will always have one valid IP - use
	//			// this IP address.
	//			alloc = &aws.AllocationResult{
	//				&newIf.IPv4s[0],
	//				*newIf,
	//			}
	//		}
	//	}
	//
	//	registry.ForgetIP(*alloc.IP)
	//
	//	eni := v2.ENI{
	//		ID:            alloc.Interface.ID,
	//		MAC:           alloc.Interface.Mac,
	//		InterfaceName: alloc.Interface.IfName,
	//		Number:        alloc.Interface.Number,
	//		Addresses:     []string{},
	//		Subnet: v2.AwsSubnet{
	//			ID: alloc.Interface.SubnetID,
	//		},
	//		VPC: v2.AwsVPC{
	//			ID:    alloc.Interface.VpcID,
	//			CIDRs: []string{},
	//		},
	//		SecurityGroups: alloc.Interface.SecurityGroupIds,
	//	}
	//
	//	if alloc.Interface.SubnetCidr != nil {
	//		eni.Subnet.CIDR = alloc.Interface.SubnetCidr.String()
	//	}
	//
	//	if alloc.Interface.VpcPrimaryCidr != nil {
	//		eni.VPC.PrimaryCIDR = alloc.Interface.VpcPrimaryCidr.String()
	//	}
	//
	//	for _, ip := range alloc.Interface.VpcCidrs {
	//		eni.VPC.CIDRs = append(eni.VPC.CIDRs, ip.String())
	//	}
	//
	//	for _, ip := range alloc.Interface.IPv4s {
	//		eni.Addresses = append(eni.Addresses, ip.String())
	//	}
	//
	//	if node.Status.ENI.Available == nil {
	//		node.Status.ENI.Available = map[string]v2.ENI{}
	//	}
	//	node.Status.ENI.Available[alloc.IP.String()] = eni
	//
	//	log.Infof("Allocated ENI %s: %+v", alloc.IP.String(), eni)

	return nil
}

func extractRelevantENIs(enis []v2.ENI, instanceID string) []v2.ENI {
	relevantENIs := []v2.ENI{}
	for _, e := range enis {
		if e.InstanceID == instanceID {
			relevantENIs = append(relevantENIs, e)
		}
	}
	return relevantENIs
}

func makeExistingENIsAvailable(enis []v2.ENI, node *v2.CiliumNode) {
	node.Status.ENI.ENIs = map[string]v2.ENI{}
	for _, e := range enis {
		node.Status.ENI.ENIs[e.ID] = e

		for _, ip := range e.Addresses {
			if _, ok := node.Status.ENI.AvailableIPs[ip]; !ok {
				node.Status.ENI.AvailableIPs[ip] = e.ID
			}
		}
	}
}

func refreshNode(enis []v2.ENI, node *v2.CiliumNode) error {
	if node.Status.ENI.AvailableIPs == nil {
		node.Status.ENI.AvailableIPs = map[string]string{}
	}

	relevantENIs := extractRelevantENIs(enis, node.Spec.ENI.InstanceID)
	makeExistingENIsAvailable(relevantENIs, node)

	//	registry := &lyftaws.Registry{}
	//
	//	requiredAddresses := node.Spec.ENI.PreAllocate
	//	if requiredAddresses == 0 {
	//		requiredAddresses = defaultPreAllocation
	//	}
	//
	//	availableAddresses := len(node.Status.ENI.Available)
	//	needed := requiredAddresses - availableAddresses
	//
	//	for _, ipString := range node.Status.ENI.Released {
	//		ip := net.ParseIP(ipString)
	//		if ip == nil {
	//			log.Warning("Ignoring invalid ip \"%s\" in CiliumNode %s", ipString, node.Name)
	//			continue
	//		}
	//
	//		registry.TrackIP(ip)
	//	}
	//
	//	node.Status.ENI.Released = []string{}
	//
	//	if needed > 0 {
	//		log.Debugf("Need to allocate %d additional ENI addresses", needed)
	//
	//		if err := allocate(node); err != nil {
	//			return err
	//		}
	//
	//
	//		log.Infof("Updated CiliumNode to %+v", node)
	//	}

	var err error
	k8sCapabilities := k8sversion.Capabilities()
	switch {
	case k8sCapabilities.UpdateStatus:
		_, err = ciliumK8sClient.CiliumV2().CiliumNodes("default").UpdateStatus(node)
	default:
		_, err = ciliumK8sClient.CiliumV2().CiliumNodes("default").Update(node)
	}

	return err
}

func jitter(d time.Duration, pct float64) time.Duration {
	jitter := rand.Int63n(int64(float64(d) * pct))
	d += time.Duration(jitter)
	return d
}

func eniGC() error {
	reg := &lyftaws.Registry{}
	freeAfter := time.Minute
	// Insert free-after jitter of 15% of the period
	freeAfter = jitter(freeAfter, 0.15)

	// Invert free-after
	freeAfter *= -1

	ips, err := reg.TrackedBefore(time.Now().Add(freeAfter))
	if err != nil {
		return err
	}

	for _, ip := range ips {
		err := lyftaws.DefaultClient.DeallocateIP(&ip)
		if err == nil {
			reg.ForgetIP(ip)
			log.Info("Released IP %s for use", ip)
		} else {
			log.WithError(err).Warning("Cannot deallocate %s", ip)
		}
	}

	return nil
}

func startENIAllocator() error {
	log.Info("Starting ENI allocator...")

	awsSession = session.Must(session.NewSession())
	metadataClient = ec2metadata.New(awsSession)

	instance, err := metadataClient.GetInstanceIdentityDocument()
	if err != nil {
		return fmt.Errorf("unable to retrieve instance identity document: %s", err)
	}

	identityDocument = &instance
	ec2Client = ec2.New(awsSession, aws.NewConfig().WithRegion(identityDocument.Region))

	mngr := controller.NewManager()
	mngr.UpdateController("eni-allocator",
		controller.ControllerParams{
			RunInterval: 5 * time.Second,
			DoFunc: func(_ context.Context) error {
				log.Debugf("Running ENI controller...")

				enis, err := getInterfaces()
				if err != nil {
					return err
				}
				for _, obj := range ciliumNodeStore.List() {
					log.Debugf("Looking at node %+v", obj)
					if node, ok := obj.(*v2.CiliumNode); ok {
						cpy := node.DeepCopy()
						if err := refreshNode(enis, cpy); err != nil {
							log.WithError(err).Warning("Refreshing ENI node failed")
						}
					}
				}

				return nil
			},
		})
	//
	//	mngr.UpdateController("eni-gc",
	//		controller.ControllerParams{
	//			RunInterval: time.Minute,
	//			DoFunc: func(_ context.Context) error {
	//				log.Debugf("Running ENI garbage collector..")
	//				err := eniGC()
	//				if err != nil {
	//					log.WithError(err).Warning("ENI garbage collector failed")
	//				}
	//				return err
	//			},
	//		})

	return nil
}
