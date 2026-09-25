// Copyright 2026 Google LLC
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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/actorlock"
	"github.com/agent-substrate/substrate/internal/ateomsuspend"
	"github.com/agent-substrate/substrate/internal/resources"
)

// fakeSuspender stands in for the control plane. onRequest decides each
// request's answer and may, like a real suspend, run the checkpoint's side
// effect of unhosting the actor.
type fakeSuspender struct {
	onRequest func(ctx context.Context, actor ateomsuspend.Actor) error

	mu       sync.Mutex
	requests []ateomsuspend.Actor
}

func (f *fakeSuspender) RequestSuspend(ctx context.Context, actor ateomsuspend.Actor) error {
	f.mu.Lock()
	f.requests = append(f.requests, actor)
	f.mu.Unlock()
	if f.onRequest != nil {
		return f.onRequest(ctx, actor)
	}
	return nil
}

func (f *fakeSuspender) requested() []ateomsuspend.Actor {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := slices.Clone(f.requests)
	slices.SortFunc(out, func(a, b ateomsuspend.Actor) int { return strings.Compare(a.UID, b.UID) })
	return out
}

func newSuspendTestService(suspender suspendRequester) *AteomService {
	return &AteomService{
		locks:            actorlock.New(),
		inFlight:         actorlock.NewInFlight(),
		actors:           map[string]*hostedActor{},
		maxActors:        4,
		suspendRequester: suspender,
	}
}

func hostRunning(s *AteomService, atespace, name, uid string) {
	s.actors[uid] = &hostedActor{
		attribution: resources.ActorAttribution{Ref: resources.ActorRef{Atespace: atespace, Name: name}, UID: uid},
		session:     &workloadSession{containers: []string{"app"}},
	}
}

// TestSuspendHostedActorsAsksOnlyForRunningActors checks that shutdown asks
// the control plane for every actor with containers, named by its atespace,
// name and UID, and not for one still booting: that boot was cancelled and
// there is nothing to checkpoint.
func TestSuspendHostedActorsAsksOnlyForRunningActors(t *testing.T) {
	suspender := &fakeSuspender{}
	s := newSuspendTestService(suspender)
	hostRunning(s, "team-a", "alice", "uid-a")
	hostRunning(s, "team-b", "bob", "uid-b")
	s.actors["uid-booting"] = &hostedActor{attribution: resources.ActorAttribution{UID: "uid-booting"}}

	s.suspendHostedActors(context.Background(), time.Now().Add(time.Minute))

	want := []ateomsuspend.Actor{
		{Atespace: "team-a", Name: "alice", UID: "uid-a"},
		{Atespace: "team-b", Name: "bob", UID: "uid-b"},
	}
	if got := suspender.requested(); !slices.Equal(got, want) {
		t.Errorf("requested suspends = %+v, want %+v", got, want)
	}
}

// TestGracefulShutdownLeavesSuspendedActorsAlone covers the path a WorkerPool
// roll takes: the control plane suspends every actor, each suspend unhosts
// its actor on the way out, and shutdown finds nothing left to stop. The
// sessions carry no runsc, so reaching for one would fail the test.
func TestGracefulShutdownLeavesSuspendedActorsAlone(t *testing.T) {
	var s *AteomService
	suspender := &fakeSuspender{}
	suspender.onRequest = func(_ context.Context, actor ateomsuspend.Actor) error {
		s.actorsMu.Lock()
		defer s.actorsMu.Unlock()
		delete(s.actors, actor.UID)
		return nil
	}
	s = newSuspendTestService(suspender)
	hostRunning(s, "team-a", "alice", "uid-a")
	hostRunning(s, "team-b", "bob", "uid-b")

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.gracefulShutdown(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("gracefulShutdown did not return")
	}
	if len(suspender.requested()) != 2 {
		t.Errorf("requested %d suspends, want 2", len(suspender.requested()))
	}
	if got := s.hostedActors(); len(got) != 0 {
		t.Errorf("%d actors still hosted after shutdown, want 0", len(got))
	}
}

// TestSuspendHostedActorsLeavesRefusedActorsRunning checks that a suspend the
// control plane refuses does not take the actor with it: the actor stays
// hosted for the caller to stop, and the refusal does not stop the other
// actor's suspend from being asked for.
func TestSuspendHostedActorsLeavesRefusedActorsRunning(t *testing.T) {
	var s *AteomService
	suspender := &fakeSuspender{}
	suspender.onRequest = func(_ context.Context, actor ateomsuspend.Actor) error {
		if actor.UID == "uid-refused" {
			return errors.New("rpc error: code = FailedPrecondition desc = actor is not RUNNING")
		}
		s.actorsMu.Lock()
		defer s.actorsMu.Unlock()
		delete(s.actors, actor.UID)
		return nil
	}
	s = newSuspendTestService(suspender)
	hostRunning(s, "team-a", "alice", "uid-a")
	hostRunning(s, "team-b", "bob", "uid-refused")

	s.suspendHostedActors(context.Background(), time.Now().Add(time.Minute))

	if len(suspender.requested()) != 2 {
		t.Errorf("requested %d suspends, want 2", len(suspender.requested()))
	}
	remaining := s.runningActors()
	if len(remaining) != 1 || remaining[0].attribution.UID != "uid-refused" {
		t.Errorf("running after suspends = %+v, want only uid-refused", remaining)
	}
}

// TestSuspendHostedActorsHonorsTheDrainDeadline checks that a suspend the
// control plane never answers is abandoned at the drain deadline rather than
// holding shutdown open for the whole suspend grace period.
func TestSuspendHostedActorsHonorsTheDrainDeadline(t *testing.T) {
	suspender := &fakeSuspender{}
	suspender.onRequest = func(ctx context.Context, _ ateomsuspend.Actor) error {
		// Like the real requester, give up when the caller's context ends.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
			return nil
		}
	}
	s := newSuspendTestService(suspender)
	hostRunning(s, "team-a", "alice", "uid-a")

	started := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.suspendHostedActors(context.Background(), time.Now().Add(200*time.Millisecond))
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("suspendHostedActors did not return at the drain deadline")
	}
	if waited := time.Since(started); waited > 5*time.Second {
		t.Errorf("waited %s, want the drain deadline to cut the request short", waited)
	}
}
