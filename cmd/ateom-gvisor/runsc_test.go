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
	"testing"

	"github.com/agent-substrate/substrate/internal/ateompath"
	"github.com/agent-substrate/substrate/internal/ocispec"
)

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

func TestPauseArgs(t *testing.T) {
	r := &runsc{
		path:     "/usr/bin/runsc",
		actorUID: "test-actor-123",
	}

	got := r.pauseArgs(ocispec.PauseContainer)
	want := []string{
		"-log-format", "json",
		"--alsologtostderr",
		"-root", ateompath.RunSCStateDir("test-actor-123"),
		"pause",
		ocispec.PauseContainer,
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("pauseArgs() = %v, want %v", got, want)
	}
}

func TestResumeArgs(t *testing.T) {
	r := &runsc{
		path:     "/usr/bin/runsc",
		actorUID: "test-actor-123",
	}

	got := r.resumeArgs(ocispec.PauseContainer)
	want := []string{
		"-log-format", "json",
		"--alsologtostderr",
		"-root", ateompath.RunSCStateDir("test-actor-123"),
		"resume",
		ocispec.PauseContainer,
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("resumeArgs() = %v, want %v", got, want)
	}
}

func TestFsCheckpointArgs(t *testing.T) {
	r := &runsc{
		path:     "/usr/bin/runsc",
		actorUID: "test-actor-123",
	}

	got := r.fsCheckpointArgs(ocispec.PauseContainer, "/checkpoints/test-actor-123")
	want := []string{
		"-log-format", "json",
		"--alsologtostderr",
		"-root", ateompath.RunSCStateDir("test-actor-123"),
		"fscheckpoint",
		"-image-path", "/checkpoints/test-actor-123",
		// A bare "/" selects the rootfs overlay upper of every container in
		// the sandbox, not only the pause container's.
		"-path", "/",
		ocispec.PauseContainer,
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("fsCheckpointArgs() = %v, want %v", got, want)
	}
}

func TestFsRestoreArgs(t *testing.T) {
	// A DATA snapshot carved out of a FULL capture holds only the durable-dir
	// tar: the sandbox must cold-boot from its images without a restore flag.
	durableOnly := t.TempDir()
	if err := os.WriteFile(filepath.Join(durableOnly, ateompath.DurableDirTarFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := fsRestoreArgs(durableOnly); got != nil {
		t.Errorf("fsRestoreArgs(durable-dir tar only) = %v, want nil", got)
	}

	fsCheckpoint := t.TempDir()
	for _, name := range []string{fsCheckpointManifestFile, "multitar.img", "pages_meta.img", "pages.img"} {
		if err := os.WriteFile(filepath.Join(fsCheckpoint, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := fsRestoreArgs(fsCheckpoint)
	want := []string{"--fs-restore-image-path", fsCheckpoint}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fsRestoreArgs(filesystem checkpoint) = %v, want %v", got, want)
	}
}
