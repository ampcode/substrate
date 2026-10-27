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

package objectstoreplugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"go.ate.dev/substrate/internal/objectstore"
	"go.ate.dev/substrate/pkg/objectstorage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// toStatus maps a plugin error to a gRPC status, keeping NotFound
// distinguishable so callers can probe for a snapshot.
func toStatus(err error) error {
	switch {
	case errors.Is(err, objectstorage.ErrObjectNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, objectstore.ErrEmptySource):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, err.Error())
	}
	// A storage service that is throttling or failing over answers 408, 429 or
	// 5xx. The backend client already retried those with a bounded backoff,
	// so exhausting it means the outage outlasted the budget, not that the
	// request is wrong. Unavailable lets atelet report the call as retryable
	// and the control plane retry the operation instead of crashing the actor.
	if desc, ok := objectstorage.DescribeServiceError(err); ok && isTransientHTTPStatus(desc.HTTPStatus) {
		slog.Info("Object-store plugin hit a transient storage service error; returning Unavailable", internalErrorAttrs(err)...)
		return status.Error(codes.Unavailable, err.Error())
	}
	// The caller sees only Internal, and atelet deliberately drops a plugin's
	// status text, so this log line is the one record of why the plugin failed.
	slog.Warn("Object-store plugin failed with an unrecognized error; returning Internal", internalErrorAttrs(err)...)
	return status.Error(codes.Internal, err.Error())
}

// isTransientHTTPStatus reports whether a storage service response with this
// status is worth retrying later: a timeout, throttling, or a server error.
func isTransientHTTPStatus(httpStatus int) bool {
	return httpStatus == http.StatusRequestTimeout || httpStatus == http.StatusTooManyRequests || httpStatus >= 500
}

// internalErrorAttrs describes err for the log without its text, which may
// quote a URI, header or credential: only what the storage backend describes
// of the service's response (see objectstorage.DescribeServiceError), and the
// Go type of err's innermost error.
func internalErrorAttrs(err error) []any {
	var attrs []any
	if desc, ok := objectstorage.DescribeServiceError(err); ok {
		attrs = append(attrs, slog.Int("http_status", desc.HTTPStatus))
		if desc.Code != "" {
			attrs = append(attrs, slog.String("service_code", desc.Code))
		}
		if desc.Message != "" {
			attrs = append(attrs, slog.String("message", desc.Message))
		}
	}
	for next := errors.Unwrap(err); next != nil; next = errors.Unwrap(err) {
		err = next
	}
	return append(attrs, slog.String("error_type", fmt.Sprintf("%T", err)))
}
