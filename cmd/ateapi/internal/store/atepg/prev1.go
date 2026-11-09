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

package atepg

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apimachinery/pkg/api/resource"

	"go.ate.dev/substrate/api/ateapi/v1"
	"go.ate.dev/substrate/cmd/ateapi/internal/store/atepg/internal/prev1pb"
)

// Upgrade of a database written by the Amp fork of Substrate before 1.0.
//
// The fork stored Actors and ActorTemplates with field numbers and types that
// 1.0 renumbered (api/ateapi/v1/ateapi.proto differs from the fork's
// pkg/proto/ateapipb/ateapi.proto in Actor, ActorStatus, ActorState,
// ActorTemplate, Container.resources, Volume and SnapshotConfig). Read with the
// 1.0 descriptors, such a row decodes to nonsense, and a suspended Actor
// would be unrecoverable. upgradePreV1Records runs once, on the first 1.0
// ate-api-server start after Goose has brought the schema up, and rewrites
// every stored Actor and ActorTemplate in the 1.0 encoding.
//
// It also drops what cannot be carried over: Worker records (the fork's Worker
// message was restructured and the pre-1.0 worker pods are gone by then),
// their assignments and outbox events, and Tags (a Tag names a project snapshot
// an operator agreed to lose on this upgrade). Suspended Actors keep their
// durable snapshots and resume on a 1.0 worker; an Actor in any other state
// was not paused before the upgrade and is marked CRASHED with a message that
// says so.
//
// The fork also recorded Goose versions 2 and 3 for tables that 1.0 creates in
// 000001_initial.sql. Those ledger rows are removed so a future upstream
// migration 000002 is not mistaken for already applied.
//
// Before rewriting, the affected tables are copied to amp_pre_v1_<table> in
// the same schema, so the pre-upgrade rows can be inspected or restored by
// hand. The marker table amp_pre_v1_upgrade records that the upgrade ran; a
// fresh 1.0 install writes the marker and nothing else.

const (
	preV1MarkerTable = "amp_pre_v1_upgrade"
	preV1LockName    = "agent-substrate:atepg:amp-pre-v1-upgrade"
	preV1CrashReason = "The Amp Substrate 1.0 upgrade found this actor running, not suspended, so its state was not carried over."
)

// preV1Tables are the tables whose rows are copied aside before the upgrade.
// workers and worker_assignments are deleted; the others are rewritten or, for
// tags, deleted.
var preV1Tables = []string{"actors", "actor_templates", "tags", "workers", "worker_assignments"}

// preV1Report is what one run of upgradePreV1Records did.
type preV1Report struct {
	Templates int
	Actors    int
	Crashed   int
	Tags      int64
	Workers   int64
}

// upgradePreV1Records re-encodes a pre-1.0 fork database once; see the file
// comment. It is idempotent: a concurrent or later start finds the marker and
// returns.
func upgradePreV1Records(ctx context.Context, pool *pgxpool.Pool) error {
	started := time.Now()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin pre-1.0 upgrade: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1 || ':' || current_schema(), 0))`, preV1LockName); err != nil {
		return fmt.Errorf("lock pre-1.0 upgrade: %w", err)
	}
	var done, preV1 bool
	if err := tx.QueryRow(ctx, `
		SELECT
			to_regclass($1) IS NOT NULL,
			EXISTS (SELECT 1 FROM `+migrationTableName+` WHERE version_id IN (2, 3))`,
		preV1MarkerTable).Scan(&done, &preV1); err != nil {
		return fmt.Errorf("check pre-1.0 upgrade state: %w", err)
	}
	if done {
		return nil
	}

	var report preV1Report
	if preV1 {
		report, err = rewritePreV1Records(ctx, tx)
		if err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
		CREATE TABLE `+preV1MarkerTable+` (
			upgraded_at   timestamptz NOT NULL DEFAULT now(),
			from_pre_v1   boolean NOT NULL,
			templates     integer NOT NULL,
			actors        integer NOT NULL,
			crashed       integer NOT NULL,
			tags          bigint NOT NULL,
			workers       bigint NOT NULL
		)`); err != nil {
		return fmt.Errorf("create pre-1.0 upgrade marker: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO `+preV1MarkerTable+` (from_pre_v1, templates, actors, crashed, tags, workers)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		preV1, report.Templates, report.Actors, report.Crashed, report.Tags, report.Workers); err != nil {
		return fmt.Errorf("record pre-1.0 upgrade: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit pre-1.0 upgrade: %w", err)
	}
	if preV1 {
		slog.InfoContext(ctx, "Upgraded pre-1.0 records",
			slog.Int("templates", report.Templates),
			slog.Int("actors", report.Actors),
			slog.Int("crashed", report.Crashed),
			slog.Int64("tags_deleted", report.Tags),
			slog.Int64("workers_deleted", report.Workers),
			slog.Duration("duration", time.Since(started)))
	}
	return nil
}

func rewritePreV1Records(ctx context.Context, tx pgx.Tx) (preV1Report, error) {
	var report preV1Report
	for _, table := range preV1Tables {
		backup := pgx.Identifier{"amp_pre_v1_" + table}.Sanitize()
		if _, err := tx.Exec(ctx, `CREATE TABLE `+backup+` AS TABLE `+pgx.Identifier{table}.Sanitize()); err != nil {
			return report, fmt.Errorf("copy %s before the pre-1.0 upgrade: %w", table, err)
		}
	}

	templates, err := rewritePreV1Rows(ctx, tx, "actor_templates", func(b []byte) ([]byte, bool, error) {
		old := &prev1pb.ActorTemplate{}
		if err := proto.Unmarshal(b, old); err != nil {
			return nil, false, err
		}
		converted, err := convertPreV1ActorTemplate(old)
		if err != nil {
			return nil, false, err
		}
		out, err := proto.Marshal(converted)
		return out, false, err
	})
	if err != nil {
		return report, err
	}
	report.Templates = templates.rows

	now := timestamppb.Now()
	actors, err := rewritePreV1Rows(ctx, tx, "actors", func(b []byte) ([]byte, bool, error) {
		old := &prev1pb.Actor{}
		if err := proto.Unmarshal(b, old); err != nil {
			return nil, false, err
		}
		converted, err := convertPreV1Actor(old)
		if err != nil {
			return nil, false, err
		}
		crashed := false
		if converted.GetStatus().GetState() != ateapi.ActorState_ACTOR_STATE_SUSPENDED {
			crashed = true
			converted.Status.State = ateapi.ActorState_ACTOR_STATE_CRASHED
			converted.Status.Crash = &ateapi.ActorCrash{Message: preV1CrashReason, CrashTime: now}
		}
		out, err := proto.Marshal(converted)
		return out, crashed, err
	})
	if err != nil {
		return report, err
	}
	report.Actors = actors.rows
	report.Crashed = actors.flagged

	// Mark the outbox trimmed past every pre-1.0 event before deleting them, so
	// a watcher that holds an older cursor rebuilds from the workers table.
	if _, err := tx.Exec(ctx, `
		INSERT INTO worker_outbox_trim (xid)
		SELECT xid FROM worker_outbox ORDER BY xid DESC LIMIT 1
		ON CONFLICT (id) DO UPDATE SET xid = EXCLUDED.xid
		WHERE EXCLUDED.xid > worker_outbox_trim.xid`); err != nil {
		return report, fmt.Errorf("record the outbox trim mark for the pre-1.0 upgrade: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM worker_outbox`); err != nil {
		return report, fmt.Errorf("delete pre-1.0 outbox events: %w", err)
	}
	// worker_assignments cascade from workers.
	workers, err := tx.Exec(ctx, `DELETE FROM workers`)
	if err != nil {
		return report, fmt.Errorf("delete pre-1.0 workers: %w", err)
	}
	report.Workers = workers.RowsAffected()
	tags, err := tx.Exec(ctx, `DELETE FROM tags`)
	if err != nil {
		return report, fmt.Errorf("delete pre-1.0 tags: %w", err)
	}
	report.Tags = tags.RowsAffected()
	if _, err := tx.Exec(ctx, `DELETE FROM `+migrationTableName+` WHERE version_id IN (2, 3)`); err != nil {
		return report, fmt.Errorf("remove the fork's migration ledger rows: %w", err)
	}
	return report, nil
}

type rewriteCount struct {
	rows    int
	flagged int
}

// rewritePreV1Rows passes every proto in table through rewrite and stores the
// result. rewrite reports whether the row is one the caller counts separately.
func rewritePreV1Rows(ctx context.Context, tx pgx.Tx, table string, rewrite func([]byte) ([]byte, bool, error)) (rewriteCount, error) {
	ident := pgx.Identifier{table}.Sanitize()
	rows, err := tx.Query(ctx, `SELECT atespace, name, proto FROM `+ident+` ORDER BY atespace, name`)
	if err != nil {
		return rewriteCount{}, fmt.Errorf("read pre-1.0 %s: %w", table, err)
	}
	type row struct {
		atespace, name string
		proto          []byte
	}
	stored, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var out row
		err := r.Scan(&out.atespace, &out.name, &out.proto)
		return out, err
	})
	if err != nil {
		return rewriteCount{}, fmt.Errorf("read pre-1.0 %s: %w", table, err)
	}
	var count rewriteCount
	for _, r := range stored {
		rewritten, flagged, err := rewrite(r.proto)
		if err != nil {
			return count, fmt.Errorf("convert pre-1.0 %s %s/%s: %w", table, r.atespace, r.name, err)
		}
		if _, err := tx.Exec(ctx, `UPDATE `+ident+` SET proto = $1 WHERE atespace = $2 AND name = $3`, rewritten, r.atespace, r.name); err != nil {
			return count, fmt.Errorf("write %s %s/%s: %w", table, r.atespace, r.name, err)
		}
		count.rows++
		if flagged {
			count.flagged++
		}
	}
	return count, nil
}

// convertPreV1Actor returns the 1.0 encoding of a pre-1.0 Actor. The worker
// assignment and node are dropped (the worker no longer exists), as are
// snapshots that exist only on a node: the only snapshot a 1.0 worker can
// restore is a completed durable one, so each kept snapshot loses its locality
// and resumes from object storage.
func convertPreV1Actor(old *prev1pb.Actor) (*ateapi.Actor, error) {
	out := &ateapi.Actor{
		Metadata:       &ateapi.ResourceMetadata{},
		ActorTemplate:  &ateapi.ObjectRef{},
		WorkerSelector: &ateapi.Selector{},
	}
	if err := errors.Join(
		rewire(old.GetMetadata(), out.Metadata),
		rewire(old.GetActorTemplate(), out.ActorTemplate),
		rewire(old.GetWorkerSelector(), out.WorkerSelector),
	); err != nil {
		return nil, err
	}
	if old.GetSourceTag() != nil {
		out.SourceTag = &ateapi.ObjectRef{}
		if err := rewire(old.GetSourceTag(), out.SourceTag); err != nil {
			return nil, err
		}
	}
	oldStatus := old.GetStatus()
	status := &ateapi.ActorStatus{
		State:                  convertPreV1ActorState(oldStatus.GetState()),
		LastAssignedGeneration: oldStatus.GetLastAssignedGeneration(),
	}
	if oldStatus.GetCrash() != nil {
		status.Crash = &ateapi.ActorCrash{}
		if err := rewire(oldStatus.GetCrash(), status.Crash); err != nil {
			return nil, err
		}
	}
	if volumes := oldStatus.GetExternalVolumes(); len(volumes) > 0 {
		status.ExternalVolumes = &ateapi.ExternalVolumes{}
		for _, v := range volumes {
			status.ExternalVolumes.Volumes = append(status.ExternalVolumes.Volumes, &ateapi.ExternalVolumeStatus{
				Name:            v.GetName(),
				StorageVolumeId: v.GetStorageVolumeId(),
				VolumeType:      v.GetVolumeType(),
				VolumeContext:   v.GetVolumeContext(),
			})
		}
	}
	for _, snap := range oldStatus.GetSnapshots() {
		if snap.GetDurableSnapshot().GetStatus() != prev1pb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_COMPLETED {
			continue
		}
		converted := &ateapi.Snapshot{}
		if err := rewire(snap, converted); err != nil {
			return nil, err
		}
		converted.Locality = ""
		status.Snapshots = append(status.Snapshots, converted)
	}
	out.Status = status
	return out, nil
}

func convertPreV1ActorState(s prev1pb.ActorState) ateapi.ActorState {
	switch s {
	case prev1pb.ActorState_ACTOR_STATE_RESUMING:
		return ateapi.ActorState_ACTOR_STATE_RESUMING
	case prev1pb.ActorState_ACTOR_STATE_RUNNING:
		return ateapi.ActorState_ACTOR_STATE_RUNNING
	case prev1pb.ActorState_ACTOR_STATE_SUSPENDING:
		return ateapi.ActorState_ACTOR_STATE_SUSPENDING
	case prev1pb.ActorState_ACTOR_STATE_SUSPENDED:
		return ateapi.ActorState_ACTOR_STATE_SUSPENDED
	case prev1pb.ActorState_ACTOR_STATE_CRASHED:
		return ateapi.ActorState_ACTOR_STATE_CRASHED
	case prev1pb.ActorState_ACTOR_STATE_DELETING:
		return ateapi.ActorState_ACTOR_STATE_DELETING
	case prev1pb.ActorState_ACTOR_STATE_REVERTING:
		return ateapi.ActorState_ACTOR_STATE_REVERTING
	default:
		return ateapi.ActorState_ACTOR_STATE_UNSPECIFIED
	}
}

// convertPreV1ActorTemplate returns the 1.0 encoding of a pre-1.0
// ActorTemplate.
func convertPreV1ActorTemplate(old *prev1pb.ActorTemplate) (*ateapi.ActorTemplate, error) {
	out := &ateapi.ActorTemplate{
		Metadata:       &ateapi.ResourceMetadata{},
		WorkerSelector: &ateapi.Selector{},
	}
	if err := errors.Join(
		rewire(old.GetMetadata(), out.Metadata),
		rewire(old.GetWorkerSelector(), out.WorkerSelector),
	); err != nil {
		return nil, err
	}
	for _, c := range old.GetContainers() {
		converted, err := convertPreV1Container(c)
		if err != nil {
			return nil, err
		}
		out.Containers = append(out.Containers, converted)
	}
	for _, v := range old.GetVolumes() {
		converted, err := convertPreV1Volume(v)
		if err != nil {
			return nil, err
		}
		out.Volumes = append(out.Volumes, converted)
	}
	if cfg := old.GetSnapshotConfig(); cfg != nil {
		out.SnapshotConfig = &ateapi.SnapshotConfig{
			StorageLocation:   cfg.GetStorageLocation(),
			PreferredFidelity: ateapi.SnapshotFidelity(cfg.GetPreferredFidelity()),
		}
		if golden := cfg.GetGoldenSnapshotConfig(); golden != nil {
			out.SnapshotConfig.GoldenSnapshotConfig = &ateapi.GoldenSnapshotConfig{}
			if err := rewire(golden, out.SnapshotConfig.GoldenSnapshotConfig); err != nil {
				return nil, err
			}
		}
	}
	if old.GetResources() != nil {
		resources, err := convertPreV1Resources(old.GetResources())
		if err != nil {
			return nil, err
		}
		out.Resources = resources
	}
	if old.GetStatus() != nil {
		out.Status = &ateapi.ActorTemplateStatus{}
		if err := rewire(old.GetStatus(), out.Status); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func convertPreV1Container(old *prev1pb.Container) (*ateapi.Container, error) {
	out := &ateapi.Container{
		Name:    old.GetName(),
		Image:   old.GetImage(),
		Command: old.GetCommand(),
		Args:    old.GetArgs(),
	}
	for _, e := range old.GetEnv() {
		converted := &ateapi.EnvVar{}
		if err := rewire(e, converted); err != nil {
			return nil, err
		}
		out.Env = append(out.Env, converted)
	}
	if old.GetWakeupProbe() != nil {
		out.WakeupProbe = &ateapi.WakeupProbe{}
		if err := rewire(old.GetWakeupProbe(), out.WakeupProbe); err != nil {
			return nil, err
		}
	}
	for _, m := range old.GetVolumeMounts() {
		converted := &ateapi.VolumeMount{}
		if err := rewire(m, converted); err != nil {
			return nil, err
		}
		out.VolumeMounts = append(out.VolumeMounts, converted)
	}
	if old.GetSecurityContext() != nil {
		out.SecurityContext = &ateapi.SecurityContext{}
		if err := rewire(old.GetSecurityContext(), out.SecurityContext); err != nil {
			return nil, err
		}
	}
	if old.GetResources() != nil {
		resources, err := convertPreV1Resources(old.GetResources())
		if err != nil {
			return nil, err
		}
		out.Resources = resources
	}
	return out, nil
}

// convertPreV1Resources turns the fork's named Kubernetes quantities into
// 1.0's cpu_millicores and memory_bytes.
func convertPreV1Resources(old *prev1pb.Resources) (*ateapi.ResourceRequirements, error) {
	limits := &ateapi.Resources{}
	for _, l := range old.GetLimits() {
		q, err := resource.ParseQuantity(l.GetQuantity())
		if err != nil {
			return nil, fmt.Errorf("limit %s=%q: %w", l.GetName(), l.GetQuantity(), err)
		}
		switch l.GetName() {
		case "cpu":
			limits.CpuMillicores = q.MilliValue()
		case "memory":
			limits.MemoryBytes = q.Value()
		default:
			return nil, fmt.Errorf("limit %s=%q: 1.0 has no such resource", l.GetName(), l.GetQuantity())
		}
	}
	return &ateapi.ResourceRequirements{Limits: limits}, nil
}

func convertPreV1Volume(old *prev1pb.Volume) (*ateapi.Volume, error) {
	out := &ateapi.Volume{Name: old.GetName()}
	if old.GetDurableDir() != nil {
		out.DurableDir = &ateapi.DurableDirVolumeSource{}
	}
	if tmpl := old.GetExternalVolumeTemplate(); tmpl != nil {
		capacity, err := resource.ParseQuantity(tmpl.GetCapacity())
		if err != nil {
			return nil, fmt.Errorf("volume %s capacity %q: %w", old.GetName(), tmpl.GetCapacity(), err)
		}
		out.External = &ateapi.ExternalVolumeSource{Template: &ateapi.ExternalVolumeTemplate{
			CapacityBytes:    capacity.Value(),
			StorageClassName: tmpl.GetStorageClassName(),
		}}
	}
	if info := old.GetSystemInfo(); info != nil {
		out.SystemInfo = &ateapi.SystemInfoVolumeSource{}
		for _, src := range info.GetDataSources() {
			converted := &ateapi.SystemInfoDataSource{}
			if md := src.GetActorMetadata(); md != nil {
				converted.ActorMetadata = &ateapi.ActorMetadataDataSource{}
				if err := rewire(md, converted.ActorMetadata); err != nil {
					return nil, err
				}
			}
			// TrustBundleDataSource.names moved from field 3 to field 1.
			if tb := src.GetTrustBundle(); tb != nil {
				converted.TrustBundle = &ateapi.TrustBundleDataSource{Names: tb.GetNames()}
			}
			out.SystemInfo.DataSources = append(out.SystemInfo.DataSources, converted)
		}
	}
	if old.GetImage() != nil {
		out.Image = &ateapi.ImageVolumeSource{}
		if err := rewire(old.GetImage(), out.Image); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// rewire copies src into dst through the wire format. It is only correct for
// a pair of messages whose fields have the same numbers and types in both
// versions; convertPreV1* uses it for the messages 1.0 left unchanged and
// spells out the others field by field.
func rewire(src, dst proto.Message) error {
	b, err := proto.Marshal(src)
	if err != nil {
		return err
	}
	return proto.Unmarshal(b, dst)
}
