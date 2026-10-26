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

// Package suspend asks the control plane, through the node-local atelet,
// to suspend an actor a worker hosts.
//
// This is the upward half of a suspend: the request travels worker -> atelet ->
// ateapi, and the suspend the control plane decides to run travels back down
// the ordinary path as a Checkpoint into the worker that asked. A caller must
// therefore hold no lock that Checkpoint needs while a request is in flight.
package suspend

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/wait"

	"go.ate.dev/substrate/internal/ateletdial"
	"go.ate.dev/substrate/internal/proto/ateletpb"
)

// requestTimeout bounds one attempt. It is generous because the control plane
// answers only once the suspend it decided to run has finished, which includes
// checkpointing the actor and uploading its snapshot.
const requestTimeout = 5 * time.Minute

// How a request that could not be delivered is retried: doubling from half a
// second up to the cap, then at the cap, for as long as the caller's context
// lasts.
//
// The caller's context is the whole budget. The only caller today is a worker
// shutting down, and its deadline is suspendGracePeriod in ateworker: a worker
// pod leaving is the one time an actor is suspended on its own behalf, and
// giving up early ends the actor CRASHED with its state lost. The control plane
// being out of reach for minutes is a case that happens -- an atelet rolled off
// the node before its replacement is up -- and is worth waiting out, because
// the alternative is strictly worse. A caller with a signal that decays, such
// as an idleness report, bounds its own context instead.
const (
	retryInterval = 500 * time.Millisecond
	retryCap      = 10 * time.Second
	retryFactor   = 2.0
	retryJitter   = 0.2
)

func retryBackoff() wait.Backoff {
	return wait.Backoff{
		Duration: retryInterval,
		Cap:      retryCap,
		Factor:   retryFactor,
		Jitter:   retryJitter,
		// Steps only limits how often the interval grows before it holds at
		// the cap. It does not bound the attempts; the caller's context does.
		Steps: 1 << 30,
	}
}

// Config is what a worker needs to reach the atelet on its node.
type Config struct {
	SocketPath           string
	CredentialBundlePath string
	TrustBundlePath      string
	// AteletSPIFFEID is the identity the node-local atelet must present. It
	// names atelet's namespace, not this worker's, so it is configured rather
	// than derived from the downward API.
	AteletSPIFFEID string
}

// Requester asks for suspends of the actors one worker hosts.
type Requester struct {
	socketPath string
	tlsConfig  *tls.Config
}

// NewRequester loads the worker's credentials once, at startup, so a
// misconfiguration surfaces there rather than at the first request.
func NewRequester(cfg Config) (*Requester, error) {
	tlsConfig, err := ateletdial.TLSConfig(cfg.CredentialBundlePath, cfg.TrustBundlePath, cfg.AteletSPIFFEID)
	if err != nil {
		return nil, fmt.Errorf("suspend requester: %w", err)
	}
	return &Requester{socketPath: cfg.SocketPath, tlsConfig: tlsConfig}, nil
}

// Actor names the actor to suspend. The UID pins the request to the
// incarnation the worker is hosting, so a request cannot outlive its actor and
// suspend a recreation that took the same name.
type Actor struct {
	Atespace string
	Name     string
	UID      string
}

// RequestSuspend asks that the named actor be suspended, and reports what the
// control plane answered.
//
// It retries a request that could not be delivered until ctx ends. The caller
// may have only one chance to ask -- a worker shutting down asks once per actor
// and stops whatever was not suspended -- so a failure to reach the control
// plane must not be the reason an actor crashes while the caller still has
// time to wait. The caller's context is the budget.
//
// A refusal is not retried. The control plane declining -- the actor is no
// longer assigned to this worker, or a resume, pause, or delete won the race --
// is an answer, and asking again cannot change it.
func (r *Requester) RequestSuspend(ctx context.Context, actor Actor) error {
	// A fresh connection per request picks up rotated worker credentials and
	// re-verifies atelet. Requests are rare enough that the handshake costs
	// nothing next to the suspend it asks for. Retries share it: gRPC
	// reconnects underneath, reloading the credentials as it does.
	conn, err := ateletdial.Dial(r.socketPath, r.tlsConfig)
	if err != nil {
		return fmt.Errorf("dial atelet: %w", err)
	}
	defer conn.Close()
	return requestWithRetry(ctx, conn, actor, retryBackoff())
}

// requestWithRetry sends the request until it is answered or ctx ends. The
// connection and backoff are parameters so the loop can be exercised without a
// socket or certificates.
//
// The loop is spelled out rather than handed to wait.ExponentialBackoffWithContext,
// which stops once the backoff reaches its cap; here the cap is where the
// interval settles, not where the asking stops.
func requestWithRetry(ctx context.Context, conn grpc.ClientConnInterface, actor Actor, backoff wait.Backoff) error {
	// The last failure to reach the control plane, so that when the context
	// ends the error says what kept failing rather than only that time passed.
	var lastErr error
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return gaveUp(attempt-1, err, lastErr)
		}
		err := requestOnce(ctx, conn, actor)
		if err == nil {
			return nil
		}
		if !retryable(err) {
			// An attempt the context cut short while earlier ones could not
			// be delivered is the budget running out, not an answer.
			if ctxErr := ctx.Err(); ctxErr != nil && lastErr != nil {
				return gaveUp(attempt, ctxErr, lastErr)
			}
			return err
		}
		lastErr = err
		slog.WarnContext(ctx, "Retrying an actor suspend request",
			slog.String("actor_atespace", actor.Atespace),
			slog.String("actor_name", actor.Name),
			slog.Int("attempt", attempt),
			slog.Any("err", err))
		select {
		case <-ctx.Done():
			return gaveUp(attempt, ctx.Err(), lastErr)
		case <-time.After(backoff.Step()):
		}
	}
}

// gaveUp is the error for a budget that ran out while the control plane was
// still out of reach. It carries both the context's error and, when there is
// one, the failure that kept the request from being delivered.
func gaveUp(attempts int, ctxErr, lastErr error) error {
	if lastErr == nil {
		return ctxErr
	}
	return fmt.Errorf("giving up on suspend request after %d attempts (%w): %w", attempts, ctxErr, lastErr)
}

// retryable reports whether err is the control plane being briefly out of
// reach or briefly busy, rather than the control plane answering.
//
// Unavailable is atelet or ateapi restarting, and ResourceExhausted is
// momentary backpressure. Aborted is contention on the actor itself, which
// ateapi returns asking to be retried. It has two sources: another operation
// holds the actor's lease, or a write lost to a concurrent one. The lease is
// the likely one here, because a suspend takes it before it does anything
// else, and it is worth waiting out -- whatever holds it finishes, and the
// retry re-runs every precondition against fresh state, so a pause or delete
// that won the race is refused rather than overridden.
//
// Everything else is left alone. NotFound and FailedPrecondition are
// decisions; PermissionDenied, Unauthenticated, and InvalidArgument are bugs
// or misconfiguration that another attempt only repeats. DeadlineExceeded is
// deliberately not retried either: an attempt reaches it only by outliving
// requestTimeout, which means the suspend itself is slow rather than
// undelivered, and re-sending would multiply a five-minute wait.
func retryable(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.Aborted, codes.ResourceExhausted:
		return true
	default:
		return false
	}
}

// requestOnce is the call itself, over an already-open connection.
func requestOnce(ctx context.Context, conn grpc.ClientConnInterface, actor Actor) error {
	callCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	_, err := ateletpb.NewWorkerSupportClient(conn).RequestActorSuspend(callCtx, &ateletpb.RequestActorSuspendRequest{
		ActorAtespace: actor.Atespace,
		ActorName:     actor.Name,
		ActorUid:      actor.UID,
	})
	return err
}
