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

package demo

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/e2e"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestGracefulWorkerTermination exercises the worker eviction flow end to end:
// an actor is scheduled onto a worker pod, that pod is deleted (simulating a
// Kubernetes eviction), and the control plane is expected to mark the worker
// DRAINING, suspend the actor it hosts, then remove the worker and detach the
// actor once the pod is gone.
//
// On gVisor the actor ends SUSPENDED: ateom-gvisor holds the sandbox after
// SIGTERM until atecontroller's SuspendActor has checkpointed it. ateom-microvm
// still forwards SIGTERM into the guest at once, so there the suspend races the
// demo actor's SIGTERM handler (which sleeps before exiting) and the actor ends
// SUSPENDED or CRASHED. We assert the control-plane state machine rather than
// any in-actor state saving, which is the application's responsibility.
func TestGracefulWorkerTermination(t *testing.T) {
	nsObj := e2e.CreateNamespace(t)

	ctx := context.Background()
	clients := e2e.GetClients()

	at, err := createActorTemplate(ctx, t, clients, nsObj, ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FULL, ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FULL, ateapipb.ResumeSource_RESUME_SOURCE_COLD_BOOT)
	if err != nil {
		t.Fatalf("failed to initialize ActorTemplate: %v", err)
	}

	actorID := "graceful-term-" + nsObj.Name
	if _, err := clients.SubstrateAPI.CreateActor(ctx, &ateapipb.CreateActorRequest{
		Actor: &ateapipb.Actor{
			Metadata:      &ateapipb.ResourceMetadata{Atespace: demoAtespace, Name: actorID},
			ActorTemplate: e2e.TemplateRef(at),
		},
	}); err != nil {
		t.Fatalf("failed to create Actor: %v", err)
	}
	defer func() {
		_, _ = clients.SubstrateAPI.DeleteActor(ctx, &ateapipb.DeleteActorRequest{
			Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
		})
	}()

	// Bring the actor up on a worker so it is bound to a pod.
	if _, err := e2e.ResumeActorAwaitCapacity(t, ctx, clients, &ateapipb.ResumeActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	}); err != nil {
		t.Fatalf("failed to resume Actor: %v", err)
	}
	waitForActorState(ctx, t, clients, actorID, ateapipb.ActorState_ACTOR_STATE_RUNNING)

	// Set the sigterm sleep interval to 15 seconds.
	if _, err := callActorPath(t, resources.ActorRef{Atespace: demoAtespace, Name: actorID}, "GET", "/set-sigterm-sleep?duration=15"); err != nil {
		t.Fatalf("failed to set sigterm sleep: %v", err)
	}

	running, err := clients.SubstrateAPI.GetActor(ctx, &ateapipb.GetActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	})
	if err != nil {
		t.Fatalf("failed to get running Actor: %v", err)
	}
	podNS := running.GetStatus().GetWorkerAssignment().GetWorkerNamespace()
	podName := running.GetStatus().GetWorkerAssignment().GetWorkerPod()
	if podNS == "" || podName == "" {
		t.Fatalf("running actor has no bound worker pod: ns=%q name=%q", podNS, podName)
	}
	t.Logf("Actor %q bound to worker pod %s/%s", actorID, podNS, podName)

	// Evict the worker pod. The kubelet sends SIGTERM to ateom; the control
	// plane marks the worker DRAINING on the DeletionTimestamp watch event,
	// suspends the actor, and cleans up the worker when the pod is finally gone.
	if err := clients.K8s.CoreV1().Pods(podNS).Delete(ctx, podName, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("failed to delete worker pod %s/%s: %v", podNS, podName, err)
	}

	// The worker record must eventually be removed once the pod is gone, which
	// waits for the checkpoint and its upload.
	if err := waitForWorkerRemoved(ctx, t, clients, podName, 180*time.Second); err != nil {
		t.Fatalf("worker %s not removed after pod deletion: %v", podName, err)
	}

	waitForActorOffWorker(ctx, t, clients, actorID, 60*time.Second)

	// Verify the pod assignment was cleared.
	actor, err := clients.SubstrateAPI.GetActor(ctx, &ateapipb.GetActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	})
	if err != nil {
		t.Fatalf("failed to get actor: %v", err)
	}
	if pod := actor.GetStatus().GetWorkerAssignment().GetWorkerPod(); pod != "" {
		t.Errorf("actor still bound to worker pod %q, expected empty", pod)
	}
}

// waitForActorOffWorker waits for an evicted actor to settle: SUSPENDED where
// the runtime holds the sandbox for the checkpoint (gVisor), SUSPENDED or CRASHED
// where the checkpoint races SIGTERM into the guest (microvm).
func waitForActorOffWorker(ctx context.Context, t *testing.T, clients *e2e.Clients, actorID string, timeout time.Duration) {
	t.Helper()
	settled := []ateapipb.ActorState{ateapipb.ActorState_ACTOR_STATE_SUSPENDED}
	if e2e.IsMicroVM() {
		settled = append(settled, ateapipb.ActorState_ACTOR_STATE_CRASHED)
	}
	t.Logf("Waiting for Actor %q to be one of %v...", actorID, settled)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := clients.SubstrateAPI.GetActor(ctx, &ateapipb.GetActorRequest{
			Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
		})
		if err == nil && slices.Contains(settled, resp.GetStatus().GetState()) {
			t.Logf("Actor %q reached state %v", actorID, resp.GetStatus().GetState())
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("timed out waiting for actor %q to reach one of %v", actorID, settled)
}

// waitForWorkerRemoved polls ListWorkers until the named worker is absent.
func waitForWorkerRemoved(ctx context.Context, t *testing.T, clients *e2e.Clients, podName string, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		resp, err := clients.SubstrateAPI.ListWorkers(ctx, &ateapipb.ListWorkersRequest{})
		if err == nil {
			found := false
			for _, w := range resp.GetWorkers() {
				if w.GetWorkerPod() == podName {
					found = true
					break
				}
			}
			if !found {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		time.Sleep(time.Second)
	}
}

// TestGracefulWorkerTerminationTimeout exercises the case where the workload
// container hangs on SIGTERM for longer than the 1-minute workloadGracePeriod.
// On gVisor SIGTERM never reaches the guest: the checkpoint atecontroller
// requests lands first and the actor ends SUSPENDED. On microvm the ateom is
// expected to SIGKILL the container unless the checkpoint beat it, and the
// actor ends CRASHED or SUSPENDED. Either way the control plane must remove
// the worker and detach the actor. Runs against both runtimes.
func TestGracefulWorkerTerminationTimeout(t *testing.T) {
	nsObj := e2e.CreateNamespace(t)

	ctx := context.Background()
	clients := e2e.GetClients()

	at, err := createActorTemplate(ctx, t, clients, nsObj, ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FULL, ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FULL, ateapipb.ResumeSource_RESUME_SOURCE_COLD_BOOT)
	if err != nil {
		t.Fatalf("failed to initialize ActorTemplate: %v", err)
	}

	actorID := "graceful-term-timeout-" + nsObj.Name
	if _, err := clients.SubstrateAPI.CreateActor(ctx, &ateapipb.CreateActorRequest{
		Actor: &ateapipb.Actor{
			Metadata:      &ateapipb.ResourceMetadata{Atespace: demoAtespace, Name: actorID},
			ActorTemplate: e2e.TemplateRef(at),
		},
	}); err != nil {
		t.Fatalf("failed to create Actor: %v", err)
	}
	defer func() {
		_, _ = clients.SubstrateAPI.DeleteActor(ctx, &ateapipb.DeleteActorRequest{
			Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
		})
	}()

	// Bring the actor up on a worker so it is bound to a pod.
	if _, err := e2e.ResumeActorAwaitCapacity(t, ctx, clients, &ateapipb.ResumeActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	}); err != nil {
		t.Fatalf("failed to resume Actor: %v", err)
	}
	waitForActorState(ctx, t, clients, actorID, ateapipb.ActorState_ACTOR_STATE_RUNNING)

	// Set the sigterm sleep interval to 90 seconds (longer than the 1-minute grace period).
	if _, err := callActorPath(t, resources.ActorRef{Atespace: demoAtespace, Name: actorID}, "GET", "/set-sigterm-sleep?duration=90"); err != nil {
		t.Fatalf("failed to set sigterm sleep: %v", err)
	}

	running, err := clients.SubstrateAPI.GetActor(ctx, &ateapipb.GetActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	})
	if err != nil {
		t.Fatalf("failed to get running Actor: %v", err)
	}
	podNS := running.GetStatus().GetWorkerAssignment().GetWorkerNamespace()
	podName := running.GetStatus().GetWorkerAssignment().GetWorkerPod()
	if podNS == "" || podName == "" {
		t.Fatalf("running actor has no bound worker pod: ns=%q name=%q", podNS, podName)
	}
	t.Logf("Actor %q bound to worker pod %s/%s", actorID, podNS, podName)

	// Evict the worker pod. The kubelet sends SIGTERM to ateom, which propagates
	// it into the sandbox; the container hangs, triggering the 1-minute timeout,
	// followed by SIGKILL by ateom.
	if err := clients.K8s.CoreV1().Pods(podNS).Delete(ctx, podName, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("failed to delete worker pod %s/%s: %v", podNS, podName, err)
	}

	// The worker record must eventually be removed once the pod is gone. On
	// microvm that is the 1-minute timeout plus up to 5s SIGKILL wait; on gVisor
	// it is the checkpoint and its upload.
	if err := waitForWorkerRemoved(ctx, t, clients, podName, 180*time.Second); err != nil {
		t.Fatalf("worker %s not removed after pod deletion: %v", podName, err)
	}

	waitForActorOffWorker(ctx, t, clients, actorID, 120*time.Second)

	// Verify the pod assignment was cleared.
	actor, err := clients.SubstrateAPI.GetActor(ctx, &ateapipb.GetActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	})
	if err != nil {
		t.Fatalf("failed to get actor: %v", err)
	}
	if pod := actor.GetStatus().GetWorkerAssignment().GetWorkerPod(); pod != "" {
		t.Errorf("actor still bound to worker pod %q, expected empty", pod)
	}
}

// TestGracefulWorkerTerminationSuspend exercises the case where a worker pod is
// deleted (evicted), and while the container is in its SIGTERM shutdown phase,
// we initiate a suspend. Suspend should succeed.
func TestGracefulWorkerTerminationSuspend(t *testing.T) {
	nsObj := e2e.CreateNamespace(t)

	ctx := context.Background()
	clients := e2e.GetClients()

	at, err := createActorTemplate(ctx, t, clients, nsObj, ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FULL, ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FULL, ateapipb.ResumeSource_RESUME_SOURCE_COLD_BOOT)
	if err != nil {
		t.Fatalf("failed to initialize ActorTemplate: %v", err)
	}

	actorID := "graceful-term-suspend-" + nsObj.Name
	if _, err := clients.SubstrateAPI.CreateActor(ctx, &ateapipb.CreateActorRequest{
		Actor: &ateapipb.Actor{
			Metadata:      &ateapipb.ResourceMetadata{Atespace: demoAtespace, Name: actorID},
			ActorTemplate: e2e.TemplateRef(at),
		},
	}); err != nil {
		t.Fatalf("failed to create Actor: %v", err)
	}
	defer func() {
		_, _ = clients.SubstrateAPI.DeleteActor(ctx, &ateapipb.DeleteActorRequest{
			Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
		})
	}()

	// Bring the actor up on a worker so it is bound to a pod.
	if _, err := e2e.ResumeActorAwaitCapacity(t, ctx, clients, &ateapipb.ResumeActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	}); err != nil {
		t.Fatalf("failed to resume Actor: %v", err)
	}
	waitForActorState(ctx, t, clients, actorID, ateapipb.ActorState_ACTOR_STATE_RUNNING)

	// Set the sigterm sleep interval to 30 seconds.
	if _, err := callActorPath(t, resources.ActorRef{Atespace: demoAtespace, Name: actorID}, "GET", "/set-sigterm-sleep?duration=30"); err != nil {
		t.Fatalf("failed to set sigterm sleep: %v", err)
	}

	running, err := clients.SubstrateAPI.GetActor(ctx, &ateapipb.GetActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	})
	if err != nil {
		t.Fatalf("failed to get running Actor: %v", err)
	}
	podNS := running.GetStatus().GetWorkerAssignment().GetWorkerNamespace()
	podName := running.GetStatus().GetWorkerAssignment().GetWorkerPod()
	if podNS == "" || podName == "" {
		t.Fatalf("running actor has no bound worker pod: ns=%q name=%q", podNS, podName)
	}
	t.Logf("Actor %q bound to worker pod %s/%s", actorID, podNS, podName)

	// Evict the worker pod. The kubelet sends SIGTERM to ateom, which propagates
	// it into the sandbox; the container hangs for 30s.
	if err := clients.K8s.CoreV1().Pods(podNS).Delete(ctx, podName, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("failed to delete worker pod %s/%s: %v", podNS, podName, err)
	}

	// Wait 2 seconds to make sure the SIGTERM was sent and the container is in its sleep phase.
	time.Sleep(2 * time.Second)

	// Suspend the actor.
	t.Logf("Suspending actor %q during termination", actorID)
	if _, err := clients.SubstrateAPI.SuspendActor(ctx, &ateapipb.SuspendActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	}); err != nil {
		t.Fatalf("failed to suspend Actor: %v", err)
	}

	// The worker record must eventually be removed once the pod is gone.
	if err := waitForWorkerRemoved(ctx, t, clients, podName, 60*time.Second); err != nil {
		t.Fatalf("worker %s not removed after pod deletion: %v", podName, err)
	}

	// Verify the actor lands in ACTOR_STATE_SUSPENDED
	waitForActorState(ctx, t, clients, actorID, ateapipb.ActorState_ACTOR_STATE_SUSPENDED)

	// Verify the pod assignment was cleared.
	actor, err := clients.SubstrateAPI.GetActor(ctx, &ateapipb.GetActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	})
	if err != nil {
		t.Fatalf("failed to get actor: %v", err)
	}
	if pod := actor.GetStatus().GetWorkerAssignment().GetWorkerPod(); pod != "" {
		t.Errorf("actor still bound to worker pod %q, expected empty", pod)
	}
}
