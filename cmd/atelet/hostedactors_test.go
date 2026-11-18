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
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.ate.dev/substrate/internal/nodepath"
	"go.ate.dev/substrate/internal/proto/ateworkerpb"
)

// hostingWorker is a worker that hosts the given actors, or fails the call.
type hostingWorker struct {
	ateworkerpb.UnimplementedWorkerServer
	actorUIDs []string
	err       error
}

func (w *hostingWorker) GetActiveWorkloadStats(context.Context, *ateworkerpb.GetActiveWorkloadStatsRequest) (*ateworkerpb.GetActiveWorkloadStatsResponse, error) {
	if w.err != nil {
		return nil, w.err
	}
	resp := &ateworkerpb.GetActiveWorkloadStatsResponse{}
	for _, uid := range w.actorUIDs {
		resp.Samples = append(resp.Samples, &ateworkerpb.WorkloadStatsSample{ActorUid: uid})
	}
	return resp, nil
}

// newWorkersDir returns an empty workers directory. Its path is short,
// because a unix socket path is limited to about 100 bytes.
func newWorkersDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "workers")
	if err != nil {
		t.Fatalf("creating workers dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// serveWorker serves worker on the socket of podUID under workersDir. The
// returned func stops it and leaves the socket file, as a killed worker does.
func serveWorker(t *testing.T, workersDir, podUID string, worker *hostingWorker) (kill func()) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(workersDir, podUID), 0o700); err != nil {
		t.Fatalf("creating worker dir: %v", err)
	}
	lis, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(workersDir, podUID, nodepath.WorkerSocketName), Net: "unix"})
	if err != nil {
		t.Fatalf("listening on worker socket: %v", err)
	}
	lis.SetUnlinkOnClose(false)
	srv := grpc.NewServer()
	ateworkerpb.RegisterWorkerServer(srv, worker)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return srv.Stop
}

func TestHostedActors(t *testing.T) {
	t.Run("no workers dir", func(t *testing.T) {
		got, err := hostedActors(t.Context(), filepath.Join(t.TempDir(), "workers"))
		if err != nil || len(got) != 0 {
			t.Fatalf("hostedActors = %v, %v; want none", got, err)
		}
	})

	// The node after a drain: the workers that hosted actors are gone and new
	// workers wait for their first actor.
	t.Run("stopped and idle workers", func(t *testing.T) {
		workers := newWorkersDir(t)
		if err := os.MkdirAll(filepath.Join(workers, "no-socket"), 0o700); err != nil {
			t.Fatalf("creating worker dir: %v", err)
		}
		serveWorker(t, workers, "killed", &hostingWorker{actorUIDs: []string{"actor-1"}})()
		serveWorker(t, workers, "idle", &hostingWorker{})
		got, err := hostedActors(t.Context(), workers)
		if err != nil || len(got) != 0 {
			t.Fatalf("hostedActors = %v, %v; want none", got, err)
		}
	})

	t.Run("workers that host actors", func(t *testing.T) {
		workers := newWorkersDir(t)
		serveWorker(t, workers, "idle", &hostingWorker{})
		serveWorker(t, workers, "one", &hostingWorker{actorUIDs: []string{"actor-1"}})
		serveWorker(t, workers, "two", &hostingWorker{actorUIDs: []string{"actor-2", "actor-3"}})
		got, err := hostedActors(t.Context(), workers)
		if err != nil {
			t.Fatalf("hostedActors: %v", err)
		}
		slices.Sort(got)
		if want := []string{"actor-1", "actor-2", "actor-3"}; !slices.Equal(got, want) {
			t.Fatalf("hostedActors = %v, want %v", got, want)
		}
	})

	t.Run("a worker that does not answer", func(t *testing.T) {
		workers := newWorkersDir(t)
		serveWorker(t, workers, "idle", &hostingWorker{})
		serveWorker(t, workers, "stuck", &hostingWorker{err: status.Error(codes.Internal, "stuck")})
		got, err := hostedActors(t.Context(), workers)
		if err == nil || !strings.Contains(err.Error(), `worker "stuck"`) {
			t.Fatalf("hostedActors = %v, %v; want an error naming the worker", got, err)
		}
	})
}
