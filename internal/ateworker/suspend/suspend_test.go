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

package suspend

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/testing/protocmp"
	"k8s.io/apimachinery/pkg/util/wait"

	"go.ate.dev/substrate/internal/proto/ateletpb"
)

// capturingAtelet stands in for the node-local atelet. It records every
// request it is sent, and answers the nth with errs[n]; once errs runs out it
// accepts. That is how a control plane that is briefly out of reach and then
// comes back is spelled here.
type capturingAtelet struct {
	ateletpb.UnimplementedWorkerSupportServer

	errs []error
	// onRequest, when set, runs with the zero-based attempt before it is
	// answered.
	onRequest func(attempt int)

	mu  sync.Mutex
	got []*ateletpb.RequestActorSuspendRequest
}

func (a *capturingAtelet) RequestActorSuspend(_ context.Context, in *ateletpb.RequestActorSuspendRequest) (*ateletpb.RequestActorSuspendResponse, error) {
	a.mu.Lock()
	attempt := len(a.got)
	a.got = append(a.got, in)
	a.mu.Unlock()

	if a.onRequest != nil {
		a.onRequest(attempt)
	}
	if attempt < len(a.errs) {
		return nil, a.errs[attempt]
	}
	return &ateletpb.RequestActorSuspendResponse{}, nil
}

// requests returns what the atelet was sent, including attempts it refused.
func (a *capturingAtelet) requests() []*ateletpb.RequestActorSuspendRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.got)
}

// testBackoff retries the way production does, without the waiting.
func testBackoff() wait.Backoff {
	b := retryBackoff()
	b.Duration = time.Millisecond
	b.Cap = time.Millisecond
	return b
}

// manyRefusals is more refusals than any test lets the atelet be asked, so a
// retry past the point under test is answered rather than accepted and shows
// up in the count.
const manyRefusals = 100

// dialCapturingAtelet serves an in-process WorkerSupport over bufconn, which
// exercises the request without a socket or certificates.
func dialCapturingAtelet(t *testing.T, atelet *capturingAtelet) *grpc.ClientConn {
	t.Helper()
	srv := grpc.NewServer()
	ateletpb.RegisterWorkerSupportServer(srv, atelet)
	lis := bufconn.Listen(1 << 20)
	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Logf("fake atelet server exited: %v", err)
		}
	}()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))
	if err != nil {
		t.Fatalf("connecting to the fake atelet: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestRequestSuspendNamesTheActor(t *testing.T) {
	atelet := &capturingAtelet{}
	conn := dialCapturingAtelet(t, atelet)

	actor := Actor{Atespace: "team-a", Name: "actor-1", UID: "actor-uid-1"}
	if err := requestWithRetry(context.Background(), conn, actor, testBackoff()); err != nil {
		t.Fatalf("requestWithRetry() failed: %v", err)
	}

	// The UID pins the request to the incarnation this worker hosts, so it
	// cannot outlive the actor and suspend whatever took its name.
	want := []*ateletpb.RequestActorSuspendRequest{{
		ActorAtespace: "team-a",
		ActorName:     "actor-1",
		ActorUid:      "actor-uid-1",
	}}
	if diff := cmp.Diff(want, atelet.requests(), protocmp.Transform()); diff != "" {
		t.Errorf("request mismatch (-want +got):\n%s", diff)
	}
}

// The reason the retry exists: a worker shutting down asks once per actor, so
// a control plane that was briefly out of reach must not be what crashes the
// actor.
func TestRequestSuspendRidesOutATransientFailure(t *testing.T) {
	atelet := &capturingAtelet{errs: []error{
		status.Error(codes.Unavailable, "atelet restarting"),
		status.Error(codes.Aborted, "concurrent update conflict, please retry"),
	}}
	conn := dialCapturingAtelet(t, atelet)

	if err := requestWithRetry(context.Background(), conn, Actor{Atespace: "team-a", Name: "actor-1", UID: "actor-uid-1"}, testBackoff()); err != nil {
		t.Fatalf("requestWithRetry() failed: %v", err)
	}
	if got := len(atelet.requests()); got != 3 {
		t.Errorf("asked %d times, want 3 (two refusals then the accepted one)", got)
	}
}

// A refusal is an answer. Asking again cannot change it, and the caller needs
// to tell a decision from a failure to ask.
func TestRequestSuspendDoesNotRetryADecision(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"not hosted here", status.Error(codes.NotFound, "Actor team-a/actor-1 not found")},
		{"lost a race", status.Error(codes.FailedPrecondition, "Actor is RESUMING")},
		{"malformed", status.Error(codes.InvalidArgument, "actor_uid is required")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			atelet := &capturingAtelet{errs: slices.Repeat([]error{tc.err}, manyRefusals)}
			conn := dialCapturingAtelet(t, atelet)

			err := requestWithRetry(context.Background(), conn, Actor{Atespace: "team-a", Name: "actor-1", UID: "actor-uid-1"}, testBackoff())
			if got, want := status.Code(err), status.Code(tc.err); got != want {
				t.Errorf("code = %v (err %v), want %v", got, err, want)
			}
			if got := len(atelet.requests()); got != 1 {
				t.Errorf("asked %d times, want 1: a refusal is not retried", got)
			}
		})
	}
}

// The budget is the caller's context, not a count of attempts. An atelet that
// was rolled off the node is gone for minutes, not seconds, and a worker with
// time left on its grace period keeps asking until the replacement is up.
// Twenty refusals is well past the six attempts an earlier budget allowed.
func TestRequestSuspendWaitsOutALongOutage(t *testing.T) {
	gone := status.Error(codes.Unavailable, `connection error: desc = "transport: Error while dialing: dial unix /var/lib/ate/worker-support.sock: connect: no such file or directory"`)
	atelet := &capturingAtelet{errs: slices.Repeat([]error{gone}, 20)}
	conn := dialCapturingAtelet(t, atelet)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := requestWithRetry(ctx, conn, Actor{Atespace: "team-a", Name: "actor-1", UID: "actor-uid-1"}, testBackoff()); err != nil {
		t.Fatalf("requestWithRetry() failed: %v", err)
	}
	if got := len(atelet.requests()); got != 21 {
		t.Errorf("asked %d times, want 21 (twenty refusals then the accepted one)", got)
	}
}

// When the context ends while the control plane is still out of reach, the
// error says what kept failing, not just that time passed.
func TestRequestSuspendGivesUpAndSaysWhy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	unavailable := status.Error(codes.Unavailable, "atelet restarting")
	atelet := &capturingAtelet{
		errs: slices.Repeat([]error{unavailable}, manyRefusals),
		// The context ends as the fifth refusal is sent, before a sixth
		// attempt can be made.
		onRequest: func(attempt int) {
			if attempt == 4 {
				cancel()
			}
		},
	}
	conn := dialCapturingAtelet(t, atelet)

	err := requestWithRetry(ctx, conn, Actor{Atespace: "team-a", Name: "actor-1", UID: "actor-uid-1"}, testBackoff())
	if err == nil {
		t.Fatal("requestWithRetry() succeeded against an atelet that refused every attempt")
	}
	if got := status.Code(err); got != codes.Unavailable {
		t.Errorf("code = %v (err %v), want Unavailable", got, err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to carry the context's end", err)
	}
	if got := len(atelet.requests()); got != 5 {
		t.Errorf("asked %d times, want 5: the context ended the asking", got)
	}
}

// The caller's context bounds the whole thing, retries included.
func TestRequestSuspendStopsWhenTheContextEnds(t *testing.T) {
	atelet := &capturingAtelet{errs: slices.Repeat([]error{status.Error(codes.Unavailable, "atelet restarting")}, manyRefusals)}
	conn := dialCapturingAtelet(t, atelet)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := requestWithRetry(ctx, conn, Actor{Atespace: "team-a", Name: "actor-1", UID: "actor-uid-1"}, testBackoff()); err == nil {
		t.Fatal("requestWithRetry() with a dead context succeeded")
	}
	if got := len(atelet.requests()); got != 0 {
		t.Errorf("asked %d times with a dead context, want 0", got)
	}
}

// The line between "could not ask" and "was answered", code by code.
func TestRetryable(t *testing.T) {
	for _, tc := range []struct {
		code codes.Code
		want bool
	}{
		{codes.Unavailable, true},
		{codes.Aborted, true},
		{codes.ResourceExhausted, true},
		{codes.NotFound, false},
		{codes.FailedPrecondition, false},
		{codes.InvalidArgument, false},
		{codes.PermissionDenied, false},
		{codes.Unauthenticated, false},
		{codes.Internal, false},
		// An attempt reaches this only by outliving requestTimeout, which means
		// the suspend itself is slow rather than undelivered.
		{codes.DeadlineExceeded, false},
	} {
		t.Run(tc.code.String(), func(t *testing.T) {
			if got := retryable(status.Error(tc.code, "")); got != tc.want {
				t.Errorf("retryable(%v) = %t, want %t", tc.code, got, tc.want)
			}
		})
	}
}

// A misconfiguration must surface at startup rather than at the first request:
// a worker that cannot reach its atelet can never give a worker slot back, and
// finding that out only when an actor goes idle hides it for as long as the
// actor is busy.
func TestNewRequesterFailsOnBadCredentials(t *testing.T) {
	_, err := NewRequester(Config{
		SocketPath:           filepath.Join(t.TempDir(), "atelet.sock"),
		CredentialBundlePath: filepath.Join(t.TempDir(), "does-not-exist.pem"),
		TrustBundlePath:      filepath.Join(t.TempDir(), "also-missing.pem"),
	})
	if err == nil {
		t.Fatal("NewRequester() with unreadable credentials succeeded, want an error the caller can exit on")
	}
}
