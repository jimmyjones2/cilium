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

package distillery

import (
	"fmt"

	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
)

var (
	globalPolicyCache = newPolicyCache()
)

// SelectorPolicy represents a cached SelectorPolicy, previously resolved from
// the policy repository and ready to be distilled against a set of identities
// to compute datapath-level policy configuration.
type SelectorPolicy interface {
	// Consume returns the policy in terms of connectivity to peer
	// Identities. The callee MUST NOT modify the returned pointer.
	Consume(owner policy.PolicyOwner, cache cache.IdentityCache) *policy.EndpointPolicy
}

// policyCache represents a cache of resolved policies for identities.
type policyCache struct {
	lock.Mutex
	policies map[*identityPkg.Identity]*cachedSelectorPolicy
}

// newPolicyCache creates a new cache of SelectorPolicy.
func newPolicyCache() *policyCache {
	return &policyCache{
		policies: make(map[*identityPkg.Identity]*cachedSelectorPolicy),
	}
}

// upsert adds the specified Identity to the policy cache, with a reference
// from the specified Endpoint, then returns the threadsafe copy of the policy
// and whether policy has been computed for this identity.
func (cache *policyCache) upsert(identity *identityPkg.Identity, ep Endpoint) SelectorPolicy {
	cache.Lock()
	defer cache.Unlock()
	cip, ok := cache.policies[identity]
	if !ok {
		cip = newCachedSelectorPolicy()
		cache.policies[identity] = cip
	}
	cip.users[ep] = struct{}{}

	return cip
}

// remove forgets about any cached SelectorPolicy that this endpoint uses.
//
// Returns true if the SelectorPolicy was removed from the cache.
func (cache *policyCache) remove(ep Endpoint) (bool, error) {
	identity := ep.GetSecurityIdentity()

	cache.Lock()
	defer cache.Unlock()
	cip, ok := cache.policies[identity]
	if !ok {
		return false, fmt.Errorf("no cached SelectorPolicy for identity %d", identity.ID)
	}

	changed := false
	delete(cip.users, ep)
	if len(cip.users) == 0 {
		// TODO: Add deferred removal window in case the SelectorPolicy
		//       may be re-used some time soon?
		delete(cache.policies, identity)
		changed = true
	}
	return changed, nil
}

// updateSelectorPolicy resolves the policy for the security identity of the
// specified endpoint and stores it internally.
//
// Returns whether the cache was updated, or an error.
//
// Must be called with repo.Mutex held for reading.
func (cache *policyCache) updateSelectorPolicy(repo PolicyRepository, ep Endpoint) (bool, error) {
	identity := ep.GetSecurityIdentity()

	cache.Lock()
	cip, ok := cache.policies[identity]
	cache.Unlock()
	if !ok {
		return false, fmt.Errorf("SelectorPolicy not found in cache for ID %d", identity.ID)
	}

	// Resolve the policies, which could fail
	identityPolicy, err := repo.ResolvePolicyLocked(identity)
	if err != nil {
		return false, err
	}

	cache.Lock()
	defer cache.Unlock()
	cip.setPolicyLocked(identityPolicy)
	return true, nil
}

// Upsert notifies the global policy cache that the specified endpoint requires
// a reference to an identity policy, and returns the cached identity policy
// for that identity.
func Upsert(ep Endpoint) SelectorPolicy {
	identity := ep.GetSecurityIdentity()
	cip := globalPolicyCache.upsert(identity, ep)
	return cip
}

// Remove a cached SelectorPolicy reference for the specified endpoint.
func Remove(ep Endpoint) error {
	_, err := globalPolicyCache.remove(ep)
	return err
}

// PolicyRepository is an interface which generates an SelectorPolicy for a
// particular Identity.
type PolicyRepository interface {
	ResolvePolicyLocked(*identityPkg.Identity) (*policy.SelectorPolicy, error)
}

// Endpoint represents a user of an SelectorPolicy. It is used for managing
// the lifetime of the cached policy.
type Endpoint interface {
	policy.PolicyOwner
}

// UpdatePolicy resolves the policy for the security identity of the specified
// endpoint and caches it for future use.
//
// The caller must provide threadsafety for iteration over the provided policy
// repository.
func UpdatePolicy(repo PolicyRepository, ep Endpoint) error {
	_, err := globalPolicyCache.updateSelectorPolicy(repo, ep)
	return err
}