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
	"errors"
	"strings"
	"testing"

	"go.ate.dev/substrate/internal/apierror"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A worker that cannot be reached reports Unavailable through the interceptor,
// so the control plane retries instead of crashing the actor; any other worker
// failure stays a plain error, which the control plane crashes the actor for.
func TestWorkerCallError(t *testing.T) {
	dial := status.Error(codes.Unavailable, "connection error: dial unix /var/lib/ate/workers/uid/worker.sock: no such file or directory")
	draining := apierror.Unavailable("worker draining: not accepting new workloads")
	restoreFailed := status.Error(codes.Internal, "`runsc restore` exit status 1")
	plain := errors.New("no sandbox record")

	tests := []struct {
		name     string
		err      error
		wantCode codes.Code
	}{
		{name: "dial failure", err: dial, wantCode: codes.Unavailable},
		{name: "worker draining", err: draining, wantCode: codes.Unavailable},
		{name: "restore failed", err: restoreFailed, wantCode: codes.Internal},
		{name: "plain error", err: plain, wantCode: codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := workerCallError("RestoreWorkload", tt.err)
			if code := apierror.Code(got); code != tt.wantCode {
				t.Fatalf("apierror.Code = %v, want %v (err: %v)", code, tt.wantCode, got)
			}
			if !strings.Contains(got.Error(), "while calling worker RestoreWorkload") || !strings.Contains(got.Error(), status.Convert(tt.err).Message()) {
				t.Fatalf("error %q does not name the rpc and the worker's error", got)
			}
			if tt.wantCode == codes.Internal && !errors.Is(got, tt.err) {
				t.Fatalf("error %v does not wrap the worker's error", got)
			}
		})
	}
}
