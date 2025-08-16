package mpc

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fystack/mpcium/pkg/infra"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/hashicorp/consul/api"
	"github.com/samber/lo"
)

const (
	ReadinessCheckPeriod = 1 * time.Second
)

type PeerRegistry interface {
	Ready() error
	ArePeersReady() bool
	WatchPeersReady(callback func())
	// Resign is called by the node when it is going to shutdown
	Resign() error
	GetReadyPeersCount() int64
	GetReadyPeersIncludeSelf() []string // get ready peers include self
	GetTotalPeersCount() int64
}

type registry struct {
	nodeID      string
	peerNodeIDs []string
	readyMap    map[string]bool
	readyCount  int64
	mu          sync.RWMutex
	ready       bool // ready is true when all peers are ready

	consulKV    infra.ConsulKV
	healthCheck messaging.DirectMessaging
}

func NewRegistry(
	nodeID string,
	peerNodeIDs []string,
	consulKV infra.ConsulKV,
	directMessaging messaging.DirectMessaging,
) *registry {
	return &registry{
		consulKV:    consulKV,
		nodeID:      nodeID,
		peerNodeIDs: getPeerIDsExceptSelf(nodeID, peerNodeIDs),
		readyMap:    make(map[string]bool),
		readyCount:  1, // self
		healthCheck: directMessaging,
	}
}

func getPeerIDsExceptSelf(nodeID string, peerNodeIDs []string) []string {
	peerIDs := make([]string, 0, len(peerNodeIDs))
	for _, peerID := range peerNodeIDs {
		if peerID != nodeID {
			peerIDs = append(peerIDs, peerID)
		}
	}
	return peerIDs
}

func (r *registry) readyKey(nodeID string) string {
	return fmt.Sprintf("ready/%s", nodeID)
}

func (r *registry) registerReadyPairs(peerIDs []string, callback func()) {
	for _, peerID := range peerIDs {
		ready, exist := r.readyMap[peerID]
		if !exist {
			atomic.AddInt64(&r.readyCount, 1)
			logger.Info("Register", "peerID", peerID)
		} else if !ready {
			atomic.AddInt64(&r.readyCount, 1)
			logger.Info("Reconnecting...", "peerID", peerID)
		}

		r.readyMap[peerID] = true
	}

	if len(peerIDs) == len(r.peerNodeIDs) && !r.ready {
		r.mu.Lock()
		r.ready = true
		r.mu.Unlock()
		time.AfterFunc(5*time.Second, callback)
	}

}

// Ready is called by the node when it complete generate preparams and starting to accept
// incoming requests
func (r *registry) Ready() error {
	k := r.readyKey(r.nodeID)

	kv := &api.KVPair{
		Key:   k,
		Value: []byte("true"),
	}

	_, err := r.consulKV.Put(kv, nil)
	if err != nil {
		return fmt.Errorf("Put ready key failed: %w", err)
	}

	_, err = r.healthCheck.Listen(r.composeHealthCheckTopic(r.nodeID), func(data []byte) {
		logger.Debug("Health check", "peerID", string(data))
	})
	if err != nil {
		return fmt.Errorf("Listen health check failed: %w", err)
	}
	return nil
}

func (r *registry) composeHealthCheckTopic(nodeID string) string {
	return fmt.Sprintf("healthcheck:%s", nodeID)
}

func (r *registry) WatchPeersReady(callback func()) {
	ticker := time.NewTicker(ReadinessCheckPeriod)
	go r.checkPeersHeath()
	// first tick is executed immediately
	for ; true; <-ticker.C {
		pairs, _, err := r.consulKV.List("ready/", nil)
		if err != nil {
			logger.Error("List ready keys failed", err)
		}

		newReadyPeerIDs := r.getReadyPeersFromKVStore(pairs)
		if len(newReadyPeerIDs) != len(r.peerNodeIDs) {
			r.mu.Lock()
			r.ready = false
			r.mu.Unlock()

			var readyPeerIDs []string
			for peerID, isReady := range r.readyMap {
				if isReady {
					readyPeerIDs = append(readyPeerIDs, peerID)
				}
			}

			disconnecteds, _ := lo.Difference(readyPeerIDs, newReadyPeerIDs)
			if len(disconnecteds) > 0 {
				for _, peerID := range disconnecteds {
					logger.Warn("Peer disconnected!", "peerID", peerID)
					r.readyMap[peerID] = false
					atomic.AddInt64(&r.readyCount, -1)
				}

			}

		}
		r.registerReadyPairs(newReadyPeerIDs, callback)
	}

}

func (r *registry) checkPeersHeath() {
	for {
		time.Sleep(5 * time.Second)
		if !r.ArePeersReady() {
			logger.Info("Peers are not ready yet", "ready", r.GetReadyPeersCount(), "expected", len(r.peerNodeIDs)+1)
		}

		pairs, _, err := r.consulKV.List("ready/", nil)
		if err != nil {
			logger.Error("List ready keys failed", err)
			continue
		}
		readyPeerIDs := r.getReadyPeersFromKVStore(pairs)
		for _, peerID := range readyPeerIDs {
			err := r.healthCheck.SendToOtherWithRetry(r.composeHealthCheckTopic(peerID), []byte(peerID), messaging.RetryConfig{
				RetryAttempt: 2,
			})
			if err != nil && strings.Contains(err.Error(), "no responders") {
				logger.Info("No response from peer", "peerID", peerID)
				_, err := r.consulKV.Delete(r.readyKey(peerID), nil)
				if err != nil {
					logger.Error("Delete ready key failed", err)
				}
			}
		}
	}
}

func (r *registry) GetReadyPeersCount() int64 {
	return atomic.LoadInt64(&r.readyCount)
}

func (r *registry) GetReadyPeersIncludeSelf() []string {
	var peerIDs []string
	for peerID, isReady := range r.readyMap {
		if isReady {
			peerIDs = append(peerIDs, peerID)
		}
	}

	peerIDs = append(peerIDs, r.nodeID) // append self
	return peerIDs
}

func (r *registry) getReadyPeersFromKVStore(kvPairs api.KVPairs) []string {
	var peers []string
	for _, k := range kvPairs {
		var peerNodeID string
		_, err := fmt.Sscanf(k.Key, "ready/%s", &peerNodeID)
		if err != nil {
			logger.Error("Parse ready key failed", err)
		}
		if peerNodeID == r.nodeID {
			continue
		}

		peers = append(peers, peerNodeID)
	}

	return peers
}

func (r *registry) ArePeersReady() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.ready
}

func (r *registry) GetTotalPeersCount() int64 {
	var self int64 = 1
	return int64(len(r.peerNodeIDs)) + self
}

func (r *registry) Resign() error {
	k := r.readyKey(r.nodeID)

	_, err := r.consulKV.Delete(k, nil)
	if err != nil {
		return fmt.Errorf("Delete ready key failed: %w", err)
	}

	return nil
}
