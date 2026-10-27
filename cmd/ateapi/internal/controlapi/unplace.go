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

package controlapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"go.ate.dev/substrate/cmd/ateapi/internal/store"
	"go.ate.dev/substrate/internal/apierror"
	"go.ate.dev/substrate/internal/ateattr"
	"go.ate.dev/substrate/internal/resources"
	"go.ate.dev/substrate/pkg/proto/ateapipb"
)

// errAssignedWorkerLost reports that a RESUMING actor's worker went away
// (deleted or draining) before the actor finished resuming on it. Nothing the
// actor accumulated since its last snapshot lives on that worker, as the
// actor never reached RUNNING there, so the resume can place it again.
var errAssignedWorkerLost = errors.New("assigned worker was lost before the actor resumed")

// actorUpdater is the store subset unplaceActor writes through.
type actorUpdater interface {
	UpdateActor(ctx context.Context, actorRef resources.ActorRef, precondition store.Precondition, mutate func(toUpdate *ateapipb.Actor) error) (*ateapipb.Actor, error)
}

// unplaceable reports whether a RESUMING actor that lost its worker can be
// returned to SUSPENDED for another placement instead of crashing. An actor
// with a provisioned external volume may have it attached to the lost
// worker's node; the paths without a volume plugin cannot detach it, so they
// keep crashing such actors.
func unplaceable(actor *ateapipb.Actor) bool {
	if actor.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_RESUMING {
		return false
	}
	return !slices.ContainsFunc(actor.GetStatus().GetExternalVolumes(), func(vol *ateapipb.ExternalVolume) bool {
		return vol.GetStorageVolumeId() != ""
	})
}

// localSnapshotPinsNode reports whether the actor's latest local snapshot
// exists only on its node: its durable copy is not COMPLETED, so a restore
// elsewhere could not download it.
func localSnapshotPinsNode(status *ateapipb.ActorStatus) bool {
	local := findLatestLocalSnapshot(status)
	if local == nil {
		return false
	}
	return local.GetDurableSnapshot().GetStatus() != ateapipb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_COMPLETED
}

// unplaceActor returns a RESUMING actor whose worker was lost to SUSPENDED
// with its assignment cleared, so the next resume schedules it again. The
// node pin is kept only while a local snapshot exists nowhere else. The
// caller releases the actor's row on the worker, if the worker still exists,
// and detaches its volumes. The write carries actor's version: a concurrent
// writer wins and the caller retries against the newer state.
func unplaceActor(ctx context.Context, st actorUpdater, actorRef resources.ActorRef, actor *ateapipb.Actor, opName, reason string) (*ateapipb.Actor, error) {
	if actor.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_RESUMING {
		return nil, fmt.Errorf("cannot unplace actor %s in state %s", actorRef, actor.GetStatus().GetState())
	}
	slog.LogAttrs(ctx, slog.LevelWarn, "Returning actor to SUSPENDED for another placement: "+reason,
		append(ateattr.ActorLogAttrs(resources.ActorAttributionFromActor(actor)),
			slog.String("worker", actor.GetStatus().GetWorkerAssignment().GetWorkerPod()))...)
	stored, err := st.UpdateActor(ctx, actorRef, store.PreconditionFrom(actor), func(toUpdate *ateapipb.Actor) error {
		toUpdate.Status.State = ateapipb.ActorState_ACTOR_STATE_SUSPENDED
		toUpdate.Status.WorkerAssignment = nil
		if !localSnapshotPinsNode(toUpdate.GetStatus()) {
			toUpdate.Status.AssignedNode = ""
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrVersionConflict) || errors.Is(err, store.ErrUIDConflict) {
			return nil, apierror.Aborted("concurrent update conflict, please retry: %w", err)
		}
		return nil, fmt.Errorf("while returning actor %s to SUSPENDED: %w", actorRef, err)
	}
	logActorStateChanged(ctx, stored, opName)
	return stored, nil
}
