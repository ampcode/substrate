// Copyright 2026 The Agent Substrate Authors
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
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"go.ate.dev/substrate/internal/nodepath"
	"go.ate.dev/substrate/internal/proto/ateworkerpb"
)

// hostedActors returns the UIDs of the actors that the workers on this node
// host, for imagecache.WithHostedActors. A worker reports an actor through
// GetActiveWorkloadStats from the moment it accepts it until its sandbox is
// gone and its rootfs overlays are unmounted, and it serves its socket until
// it has stopped every sandbox.
//
// A worker directory without a socket, or with a socket that refuses
// connections, belongs to a worker that stopped: a worker removes its socket
// on a graceful exit, and the socket of a killed worker stays behind and
// refuses. Its sandboxes ran in its pod and stopped with it. Any other
// failure returns an error, because the worker may host an actor.
func hostedActors(ctx context.Context, workersDir string) ([]string, error) {
	workers, err := os.ReadDir(workersDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("while listing workers dir %q: %w", workersDir, err)
	}
	var actorUIDs []string
	for _, worker := range workers {
		if !worker.IsDir() {
			continue
		}
		socket := filepath.Join(workersDir, worker.Name(), nodepath.WorkerSocketName)
		hosted, err := workerHostedActors(ctx, socket)
		if err != nil {
			return nil, fmt.Errorf("while asking worker %q which actors it hosts: %w", worker.Name(), err)
		}
		actorUIDs = append(actorUIDs, hosted...)
	}
	return actorUIDs, nil
}

// workerHostedActors returns the UIDs of the actors that the worker serving
// socket hosts, or none when no worker serves it.
func workerHostedActors(ctx context.Context, socket string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, statsRPCTimeout)
	defer cancel()

	// Connect before the RPC: a gRPC call reports a missing socket, a refused
	// connection, and a stuck worker all as Unavailable.
	probe, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = probe.Close()

	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	resp, err := ateworkerpb.NewWorkerClient(conn).GetActiveWorkloadStats(ctx, &ateworkerpb.GetActiveWorkloadStatsRequest{})
	if err != nil {
		return nil, err
	}
	actorUIDs := make([]string, 0, len(resp.GetSamples()))
	for _, sample := range resp.GetSamples() {
		actorUIDs = append(actorUIDs, sample.GetActorUid())
	}
	return actorUIDs, nil
}
