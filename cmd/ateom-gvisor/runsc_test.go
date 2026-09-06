//go:build linux

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
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/agent-substrate/substrate/internal/ateompath"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
)

// TestNvproxyGlobalArgs checks that runsc is told to enable nvproxy exactly when the
// worker has a GPU. The flag must be present on sandbox creation so the sentry
// initializes GPU support up front; without it the GPU subcontainer crashes.
func TestNvproxyGlobalArgs(t *testing.T) {
	dir := t.TempDir()
	old := gpuDeviceGlob
	gpuDeviceGlob = filepath.Join(dir, "nvidia[0-9]*")
	defer func() { gpuDeviceGlob = old }()

	if got := nvproxyGlobalArgs(); len(got) != 0 {
		t.Fatalf("no GPU: want no flags, got %v", got)
	}

	if err := os.WriteFile(filepath.Join(dir, "nvidia0"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got := nvproxyGlobalArgs()
	if len(got) != 1 || got[0] != "--nvproxy" {
		t.Fatalf("GPU: want [--nvproxy], got %v", got)
	}
}

func TestKillArgs(t *testing.T) {
	r := &runsc{
		path:     "/usr/bin/runsc",
		actorUID: "test-actor-123",
	}

	got := r.killArgs("my-container", "SIGTERM")
	want := []string{
		"-log-format", "json",
		"--alsologtostderr",
		"-root", ateompath.RunSCStateDir("test-actor-123"),
		"kill",
		"my-container",
		"SIGTERM",
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("killArgs() = %v, want %v", got, want)
	}
}

func TestWaitArgs(t *testing.T) {
	r := &runsc{
		path:     "/usr/bin/runsc",
		actorUID: "test-actor-123",
	}

	got := r.waitArgs("my-container")
	want := []string{
		"-log-format", "json",
		"--alsologtostderr",
		"-root", ateompath.RunSCStateDir("test-actor-123"),
		"wait",
		"my-container",
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("waitArgs() = %v, want %v", got, want)
	}
}

// TestFsCheckpointArgs checks that a filesystem checkpoint always saves the
// rootfs delta of every container ("-path /"), with durable-dir volumes added
// after it and the container name last.
func TestFsCheckpointArgs(t *testing.T) {
	r := &runsc{
		path:     "/usr/bin/runsc",
		actorUID: "test-actor-123",
	}
	prefix := []string{
		"-log-format", "json",
		"--alsologtostderr",
		"-root", ateompath.RunSCStateDir("test-actor-123"),
		"fscheckpoint",
		"-image-path", "/ckpt",
		"-path", "/",
	}

	tests := []struct {
		name        string
		durableDirs []string
		want        []string
	}{
		{
			name: "no durable dirs",
			want: append(slices.Clone(prefix), "pause"),
		},
		{
			name:        "durable dirs",
			durableDirs: []string{"/data", "/scratch"},
			want:        append(slices.Clone(prefix), "-path", "/data", "-path", "/scratch", "pause"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := r.fsCheckpointArgs("pause", "/ckpt", tc.durableDirs)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("fsCheckpointArgs() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDurableDirMountPaths(t *testing.T) {
	spec := &ateompb.WorkloadSpec{
		Containers: []*ateompb.Container{
			{
				Name: "app",
				DurableDirVolumeMounts: []*ateompb.DurableDirVolumeMount{
					{VolumeName: "data", MountPath: "/data"},
					{VolumeName: "scratch", MountPath: "/scratch"},
				},
			},
			{
				Name: "sidecar",
				DurableDirVolumeMounts: []*ateompb.DurableDirVolumeMount{
					{VolumeName: "data", MountPath: "/data"},
				},
			},
			{Name: "plain"},
		},
	}

	got := durableDirMountPaths(spec)
	want := []string{"/data", "/scratch"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("durableDirMountPaths() = %v, want %v", got, want)
	}

	if got := durableDirMountPaths(&ateompb.WorkloadSpec{Containers: []*ateompb.Container{{Name: "plain"}}}); len(got) != 0 {
		t.Errorf("durableDirMountPaths() without durable dirs = %v, want none", got)
	}
}
