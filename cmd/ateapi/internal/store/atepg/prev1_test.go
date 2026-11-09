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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"go.ate.dev/substrate/api/ateapi/v1"
	"go.ate.dev/substrate/cmd/ateapi/internal/store/atepg/internal/prev1pb"
)

func preV1Template() *prev1pb.ActorTemplate {
	return &prev1pb.ActorTemplate{
		Metadata:       &prev1pb.ResourceMetadata{Atespace: "amp", Name: "amp-orb-1a2b3c4d", Uid: "tmpl-uid", Version: 3},
		WorkerSelector: &prev1pb.Selector{MatchLabels: map[string]string{"workload": "amp-orbs", "kubernetes.io/arch": "amd64"}},
		Containers: []*prev1pb.Container{{
			Name:    "sandbox",
			Image:   "registry.example/orb@sha256:abc",
			Command: []string{"/sbin/init"},
			Args:    []string{"--foo"},
			Env:     []*prev1pb.EnvVar{{Name: "AMP_URL", Value: "https://ampcode.com"}},
			WakeupProbe: &prev1pb.WakeupProbe{
				HttpGet: &prev1pb.HttpGetAction{Path: "/healthz", Port: 80},
			},
			VolumeMounts: []*prev1pb.VolumeMount{{Name: "docker", MountPath: "/var/lib/docker"}},
			SecurityContext: &prev1pb.SecurityContext{
				Capabilities: &prev1pb.Capabilities{Add: []string{"SYS_ADMIN"}},
			},
			Resources: &prev1pb.Resources{Limits: []*prev1pb.Limits{
				{Name: "cpu", Quantity: "250m"},
				{Name: "memory", Quantity: "512Mi"},
			}},
		}},
		Volumes: []*prev1pb.Volume{
			{Name: "docker", DurableDir: &prev1pb.DurableDirVolumeSource{}},
			{Name: "orbd", Image: &prev1pb.ImageVolumeSource{Reference: "registry.example/orbd@sha256:def"}},
			{Name: "scratch", ExternalVolumeTemplate: &prev1pb.ExternalVolumeTemplate{Capacity: "10Gi", StorageClassName: "fast"}},
			{Name: "sysinfo", SystemInfo: &prev1pb.SystemInfoVolumeSource{DataSources: []*prev1pb.SystemInfoDataSource{
				{TrustBundle: &prev1pb.TrustBundleDataSource{Names: []string{"ate-ca"}}},
				{ActorMetadata: &prev1pb.ActorMetadataDataSource{Items: []*prev1pb.ActorMetadataItem{{Path: "name", Field: prev1pb.ActorMetadataField_ACTOR_METADATA_FIELD_NAME}}}},
			}}},
		},
		SnapshotConfig: &prev1pb.SnapshotConfig{
			StorageLocation:      "gs://bucket/amp-orbs/",
			PreferredFidelity:    prev1pb.SnapshotFidelity_SNAPSHOT_FIDELITY_ROOTFS,
			GoldenSnapshotConfig: &prev1pb.GoldenSnapshotConfig{Mode: prev1pb.GoldenSnapshotMode_GOLDEN_SNAPSHOT_MODE_DISABLED},
		},
		Resources: &prev1pb.Resources{Limits: []*prev1pb.Limits{
			{Name: "cpu", Quantity: "1500m"},
			{Name: "memory", Quantity: "2Gi"},
		}},
		Status: &prev1pb.ActorTemplateStatus{GoldenSnapshotStatus: &prev1pb.GoldenSnapshotStatus{
			GoldenTag: &prev1pb.ObjectRef{Atespace: "amp", Name: "golden"},
		}},
	}
}

func wantV1Template() *ateapi.ActorTemplate {
	return &ateapi.ActorTemplate{
		Metadata:       &ateapi.ResourceMetadata{Atespace: "amp", Name: "amp-orb-1a2b3c4d", Uid: "tmpl-uid", Version: 3},
		WorkerSelector: &ateapi.Selector{MatchLabels: map[string]string{"workload": "amp-orbs", "kubernetes.io/arch": "amd64"}},
		Containers: []*ateapi.Container{{
			Name:    "sandbox",
			Image:   "registry.example/orb@sha256:abc",
			Command: []string{"/sbin/init"},
			Args:    []string{"--foo"},
			Env:     []*ateapi.EnvVar{{Name: "AMP_URL", Value: "https://ampcode.com"}},
			WakeupProbe: &ateapi.WakeupProbe{
				HttpGet: &ateapi.HttpGetAction{Path: "/healthz", Port: 80},
			},
			VolumeMounts: []*ateapi.VolumeMount{{Name: "docker", MountPath: "/var/lib/docker"}},
			SecurityContext: &ateapi.SecurityContext{
				Capabilities: &ateapi.Capabilities{Add: []string{"SYS_ADMIN"}},
			},
			Resources: &ateapi.ResourceRequirements{Limits: &ateapi.Resources{CpuMillicores: 250, MemoryBytes: 512 << 20}},
		}},
		Volumes: []*ateapi.Volume{
			{Name: "docker", DurableDir: &ateapi.DurableDirVolumeSource{}},
			{Name: "orbd", Image: &ateapi.ImageVolumeSource{Reference: "registry.example/orbd@sha256:def"}},
			{Name: "scratch", External: &ateapi.ExternalVolumeSource{Template: &ateapi.ExternalVolumeTemplate{CapacityBytes: 10 << 30, StorageClassName: "fast"}}},
			{Name: "sysinfo", SystemInfo: &ateapi.SystemInfoVolumeSource{DataSources: []*ateapi.SystemInfoDataSource{
				{TrustBundle: &ateapi.TrustBundleDataSource{Names: []string{"ate-ca"}}},
				{ActorMetadata: &ateapi.ActorMetadataDataSource{Items: []*ateapi.ActorMetadataItem{{Path: "name", Field: ateapi.ActorMetadataField_ACTOR_METADATA_FIELD_NAME}}}},
			}}},
		},
		SnapshotConfig: &ateapi.SnapshotConfig{
			StorageLocation:      "gs://bucket/amp-orbs/",
			PreferredFidelity:    ateapi.SnapshotFidelity_SNAPSHOT_FIDELITY_ROOTFS,
			GoldenSnapshotConfig: &ateapi.GoldenSnapshotConfig{Mode: ateapi.GoldenSnapshotMode_GOLDEN_SNAPSHOT_MODE_DISABLED},
		},
		Resources: &ateapi.ResourceRequirements{Limits: &ateapi.Resources{CpuMillicores: 1500, MemoryBytes: 2 << 30}},
		Status: &ateapi.ActorTemplateStatus{GoldenSnapshotStatus: &ateapi.GoldenSnapshotStatus{
			GoldenTag: &ateapi.ObjectRef{Atespace: "amp", Name: "golden"},
		}},
	}
}

func preV1SuspendedActor() *prev1pb.Actor {
	return &prev1pb.Actor{
		Metadata:       &prev1pb.ResourceMetadata{Atespace: "amp", Name: "amp-thread-1", Uid: "actor-uid-1", Version: 9},
		ActorTemplate:  &prev1pb.ObjectRef{Atespace: "amp", Name: "amp-orb-1a2b3c4d"},
		WorkerSelector: &prev1pb.Selector{MatchLabels: map[string]string{"workload": "amp-orbs"}},
		SourceTag:      &prev1pb.ObjectRef{Atespace: "amp", Name: "project-snapshot"},
		Status: &prev1pb.ActorStatus{
			State:                  prev1pb.ActorState_ACTOR_STATE_SUSPENDED,
			LastAssignedGeneration: 4,
			WorkerAssignment:       &prev1pb.WorkerAssignment{WorkerPod: "amp-orbs-abcd-0", WorkerNamespace: "amp-orbs"},
			AssignedNode:           "node-1",
			ExternalVolumes: []*prev1pb.ExternalVolume{{
				Name: "scratch", StorageVolumeId: "vol-1", VolumeType: "pd.csi.storage.gke.io",
				VolumeContext: map[string]string{"zone": "us-central1-a"},
			}},
			Snapshots: []*prev1pb.Snapshot{
				{Uuid: "s-local", Generation: 2, Owner: prev1pb.SnapshotOwner_SNAPSHOT_OWNER_ACTOR, Fidelity: prev1pb.SnapshotFidelity_SNAPSHOT_FIDELITY_ROOTFS, ActorTemplateUid: "tmpl-uid", Locality: "node-1"},
				{Uuid: "s-durable", Generation: 3, Owner: prev1pb.SnapshotOwner_SNAPSHOT_OWNER_ACTOR, Fidelity: prev1pb.SnapshotFidelity_SNAPSHOT_FIDELITY_ROOTFS, ActorTemplateUid: "tmpl-uid", Locality: "node-1",
					DurableSnapshot: &prev1pb.SnapshotStorage{Status: prev1pb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_COMPLETED, Object: &prev1pb.ObjectSnapshot{SnapshotUri: "gs://bucket/amp-orbs/s-durable"}},
					SandboxRuntime:  &prev1pb.SandboxRuntime{SandboxClass: "gvisor", Version: &prev1pb.VersionedSandboxCompat{SchemaVersion: "v7"}}},
				{Uuid: "s-pending", Generation: 4, Owner: prev1pb.SnapshotOwner_SNAPSHOT_OWNER_ACTOR, Fidelity: prev1pb.SnapshotFidelity_SNAPSHOT_FIDELITY_ROOTFS, ActorTemplateUid: "tmpl-uid", Locality: "node-1",
					DurableSnapshot: &prev1pb.SnapshotStorage{Status: prev1pb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_PENDING, Object: &prev1pb.ObjectSnapshot{SnapshotUri: "gs://bucket/amp-orbs/s-pending"}}},
			},
		},
	}
}

func wantV1SuspendedActor() *ateapi.Actor {
	return &ateapi.Actor{
		Metadata:       &ateapi.ResourceMetadata{Atespace: "amp", Name: "amp-thread-1", Uid: "actor-uid-1", Version: 9},
		ActorTemplate:  &ateapi.ObjectRef{Atespace: "amp", Name: "amp-orb-1a2b3c4d"},
		WorkerSelector: &ateapi.Selector{MatchLabels: map[string]string{"workload": "amp-orbs"}},
		SourceTag:      &ateapi.ObjectRef{Atespace: "amp", Name: "project-snapshot"},
		Status: &ateapi.ActorStatus{
			State:                  ateapi.ActorState_ACTOR_STATE_SUSPENDED,
			LastAssignedGeneration: 4,
			ExternalVolumes: &ateapi.ExternalVolumes{Volumes: []*ateapi.ExternalVolumeStatus{{
				Name: "scratch", StorageVolumeId: "vol-1", VolumeType: "pd.csi.storage.gke.io",
				VolumeContext: map[string]string{"zone": "us-central1-a"},
			}}},
			Snapshots: []*ateapi.Snapshot{
				{Uuid: "s-durable", Generation: 3, Owner: ateapi.SnapshotOwner_SNAPSHOT_OWNER_ACTOR, Fidelity: ateapi.SnapshotFidelity_SNAPSHOT_FIDELITY_ROOTFS, ActorTemplateUid: "tmpl-uid",
					DurableSnapshot: &ateapi.SnapshotStorage{State: ateapi.SnapshotStorageState_SNAPSHOT_STORAGE_STATE_COMPLETED, Object: &ateapi.ObjectSnapshot{SnapshotUri: "gs://bucket/amp-orbs/s-durable"}},
					SandboxRuntime:  &ateapi.ActorSandboxRuntime{SandboxClass: "gvisor", Version: &ateapi.VersionedSandboxCompat{SchemaVersion: "v7"}}},
			},
		},
	}
}

func TestConvertPreV1ActorTemplate(t *testing.T) {
	got, err := convertPreV1ActorTemplate(preV1Template())
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(wantV1Template(), got, protocmp.Transform()); diff != "" {
		t.Errorf("converted template differs (-want +got):\n%s", diff)
	}
}

func TestConvertPreV1ActorTemplateRejectsUnknownResource(t *testing.T) {
	old := preV1Template()
	old.Resources.Limits = append(old.Resources.Limits, &prev1pb.Limits{Name: "nvidia.com/gpu", Quantity: "1"})
	if _, err := convertPreV1ActorTemplate(old); err == nil {
		t.Fatal("expected an error for a resource 1.0 cannot express")
	}
}

func TestConvertPreV1Actor(t *testing.T) {
	got, err := convertPreV1Actor(preV1SuspendedActor())
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(wantV1SuspendedActor(), got, protocmp.Transform()); diff != "" {
		t.Errorf("converted actor differs (-want +got):\n%s", diff)
	}
}

func TestConvertPreV1ActorState(t *testing.T) {
	// The renumbered values are the ones that would silently map wrong.
	for old, want := range map[prev1pb.ActorState]ateapi.ActorState{
		prev1pb.ActorState_ACTOR_STATE_CRASHED:   ateapi.ActorState_ACTOR_STATE_CRASHED,
		prev1pb.ActorState_ACTOR_STATE_DELETING:  ateapi.ActorState_ACTOR_STATE_DELETING,
		prev1pb.ActorState_ACTOR_STATE_REVERTING: ateapi.ActorState_ACTOR_STATE_REVERTING,
		prev1pb.ActorState_ACTOR_STATE_SUSPENDED: ateapi.ActorState_ACTOR_STATE_SUSPENDED,
	} {
		if got := convertPreV1ActorState(old); got != want {
			t.Errorf("%v -> %v, want %v", old, got, want)
		}
	}
}

// seedPreV1 writes rows the way the pre-1.0 fork left them: the fork's
// migration ledger, old-encoding protos, a tag, a worker with an assignment,
// and an outbox event.
func seedPreV1(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	marshal := func(m proto.Message) []byte {
		t.Helper()
		b, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	exec(`DROP TABLE IF EXISTS ` + preV1MarkerTable)
	exec(`INSERT INTO schema_migrations (version_id, is_applied) VALUES (2, true), (3, true)`)
	exec(`INSERT INTO atespaces (name, uid, version, proto) VALUES ('amp', 'as-uid', 1, $1)`,
		marshal(&ateapi.Atespace{Metadata: &ateapi.ResourceMetadata{Name: "amp", Uid: "as-uid", Version: 1}}))
	exec(`INSERT INTO actor_templates (atespace, name, uid, version, proto) VALUES ('amp', 'amp-orb-1a2b3c4d', 'tmpl-uid', 3, $1)`,
		marshal(preV1Template()))
	exec(`INSERT INTO actors (atespace, name, uid, version, proto) VALUES ('amp', 'amp-thread-1', 'actor-uid-1', 9, $1)`,
		marshal(preV1SuspendedActor()))
	running := preV1SuspendedActor()
	running.Metadata.Name, running.Metadata.Uid = "amp-thread-2", "actor-uid-2"
	running.Status.State = prev1pb.ActorState_ACTOR_STATE_RUNNING
	exec(`INSERT INTO actors (atespace, name, uid, version, proto) VALUES ('amp', 'amp-thread-2', 'actor-uid-2', 2, $1)`,
		marshal(running))
	exec(`INSERT INTO tags (atespace, name, uid, version, proto) VALUES ('amp', 'project-snapshot', 'tag-uid', 1, $1)`,
		marshal(&ateapi.Tag{Metadata: &ateapi.ResourceMetadata{Atespace: "amp", Name: "project-snapshot", Uid: "tag-uid", Version: 1}}))
	exec(`INSERT INTO workers (name, uid, version, proto) VALUES ('amp-orbs-abcd-0', 'w-uid', 5, '\x00')`)
	exec(`INSERT INTO worker_assignments (actor_uid, worker_name, proto) VALUES ('actor-uid-1', 'amp-orbs-abcd-0', '\x00')`)
	exec(`INSERT INTO worker_outbox (payload) VALUES ('\x00')`)
}

func TestUpgradePreV1Records(t *testing.T) {
	pool := migratedPool(t, "prev1_upgrade")
	seedPreV1(t, pool)
	ctx := t.Context()

	p, err := NewPersistence(ctx, pool)
	if err != nil {
		t.Fatalf("NewPersistence on a pre-1.0 database: %v", err)
	}
	p.Close()

	readProto := func(table, name string, m proto.Message) {
		t.Helper()
		var b []byte
		if err := pool.QueryRow(ctx, `SELECT proto FROM `+table+` WHERE atespace = 'amp' AND name = $1`, name).Scan(&b); err != nil {
			t.Fatalf("read %s %s: %v", table, name, err)
		}
		if err := proto.Unmarshal(b, m); err != nil {
			t.Fatalf("decode %s %s as 1.0: %v", table, name, err)
		}
	}
	gotTemplate := &ateapi.ActorTemplate{}
	readProto("actor_templates", "amp-orb-1a2b3c4d", gotTemplate)
	if diff := cmp.Diff(wantV1Template(), gotTemplate, protocmp.Transform()); diff != "" {
		t.Errorf("stored template differs (-want +got):\n%s", diff)
	}
	gotSuspended := &ateapi.Actor{}
	readProto("actors", "amp-thread-1", gotSuspended)
	if diff := cmp.Diff(wantV1SuspendedActor(), gotSuspended, protocmp.Transform()); diff != "" {
		t.Errorf("stored suspended actor differs (-want +got):\n%s", diff)
	}
	gotRunning := &ateapi.Actor{}
	readProto("actors", "amp-thread-2", gotRunning)
	if got := gotRunning.GetStatus().GetState(); got != ateapi.ActorState_ACTOR_STATE_CRASHED {
		t.Errorf("running actor state after upgrade = %v, want CRASHED", got)
	}
	if got := gotRunning.GetStatus().GetCrash().GetMessage(); got != preV1CrashReason {
		t.Errorf("running actor crash message = %q", got)
	}
	if gotRunning.GetStatus().GetCrash().GetCrashTime() == nil {
		t.Error("running actor has no crash time")
	}

	count := func(sql string, args ...any) int64 {
		t.Helper()
		var n int64
		if err := pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return n
	}
	for table, want := range map[string]int64{
		"tags": 0, "workers": 0, "worker_assignments": 0, "worker_outbox": 0,
		"amp_pre_v1_actors": 2, "amp_pre_v1_actor_templates": 1, "amp_pre_v1_tags": 1,
		"amp_pre_v1_workers": 1, "amp_pre_v1_worker_assignments": 1,
		"worker_outbox_trim": 1,
	} {
		if got := count(`SELECT count(*) FROM ` + table); got != want {
			t.Errorf("%s has %d rows after upgrade, want %d", table, got, want)
		}
	}
	if got := count(`SELECT count(*) FROM schema_migrations WHERE version_id IN (2, 3)`); got != 0 {
		t.Errorf("fork ledger rows left: %d", got)
	}
	var fromPreV1 bool
	var templates, actors, crashed int
	var tags, workers int64
	if err := pool.QueryRow(ctx, `SELECT from_pre_v1, templates, actors, crashed, tags, workers FROM `+preV1MarkerTable).Scan(
		&fromPreV1, &templates, &actors, &crashed, &tags, &workers); err != nil {
		t.Fatal(err)
	}
	if !fromPreV1 || templates != 1 || actors != 2 || crashed != 1 || tags != 1 || workers != 1 {
		t.Errorf("marker = pre_v1 %v templates %d actors %d crashed %d tags %d workers %d",
			fromPreV1, templates, actors, crashed, tags, workers)
	}

	// A second start finds the marker and leaves the converted rows alone.
	if err := upgradePreV1Records(ctx, pool); err != nil {
		t.Fatalf("second run: %v", err)
	}
	again := &ateapi.Actor{}
	readProto("actors", "amp-thread-1", again)
	if diff := cmp.Diff(gotSuspended, again, protocmp.Transform()); diff != "" {
		t.Errorf("second run changed a converted actor (-first +second):\n%s", diff)
	}
	if got := count(`SELECT count(*) FROM ` + preV1MarkerTable); got != 1 {
		t.Errorf("marker rows after second run: %d", got)
	}
}

func TestUpgradePreV1RecordsFreshInstall(t *testing.T) {
	pool := migratedPool(t, "prev1_fresh")
	var fromPreV1 bool
	var tables int
	if err := pool.QueryRow(context.Background(), `
		SELECT from_pre_v1, (SELECT count(*) FROM information_schema.tables
			WHERE table_schema = current_schema() AND table_name LIKE 'amp\_pre\_v1\_%' AND table_name <> $1)
		FROM `+preV1MarkerTable, preV1MarkerTable).Scan(&fromPreV1, &tables); err != nil {
		t.Fatal(err)
	}
	if fromPreV1 || tables != 0 {
		t.Errorf("fresh install: from_pre_v1 %v, backup tables %d", fromPreV1, tables)
	}
}
