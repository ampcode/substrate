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

package ategcs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

// azureTestClient points the SDK at a test HTTP server so it performs realistic
// request signing and response deserialization, without retry backoff.
func azureTestClient(t *testing.T, handler http.Handler) ObjectStorage {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client, err := azblob.NewClientWithNoCredential(srv.URL, &azblob.ClientOptions{
		ClientOptions: azcore.ClientOptions{Retry: policy.RetryOptions{MaxRetries: -1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return NewAzureBlobClient(client)
}

// TestAzureGetObjectClassifiesAbsence verifies which errors are classified as
// object absence (ReasonFailedGetExternalObject) versus opaque errors.
func TestAzureGetObjectClassifiesAbsence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		code       string
		wantAbsent bool
	}{
		{name: "BlobNotFound is absence", status: http.StatusNotFound, code: "BlobNotFound", wantAbsent: true},
		{name: "ContainerNotFound is absence", status: http.StatusNotFound, code: "ContainerNotFound", wantAbsent: true},
		{name: "bare 404 is absence", status: http.StatusNotFound, wantAbsent: true},
		{name: "AuthorizationPermissionMismatch is not absence", status: http.StatusForbidden, code: "AuthorizationPermissionMismatch"},
		{name: "server error is not absence", status: http.StatusInternalServerError, code: "InternalError"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := azureTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.code != "" {
					w.Header().Set("x-ms-error-code", tc.code)
				}
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(tc.status)
				if tc.code != "" {
					_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><Error><Code>` + tc.code + `</Code><Message>x</Message></Error>`))
				}
			}))
			_, err := client.GetObject(context.Background(), "ctr", "obj")
			if err == nil {
				t.Fatal("GetObject succeeded, want an error")
			}
			if got := errors.Is(err, ErrObjectNotFound); got != tc.wantAbsent {
				t.Errorf("errors.Is(err, ReasonFailedGetExternalObject) = %v, want %v (err: %v)", got, tc.wantAbsent, err)
			}
		})
	}
}

// TestAzureGetObjectRanged verifies that a blob larger than one chunk is fetched as
// byte ranges and reassembled in order, and that a smaller one is a single request.
func TestAzureGetObjectRanged(t *testing.T) {
	for _, tc := range []struct {
		name         string
		size         int64
		wantRequests int32
	}{
		{name: "small blob is one request", size: 10, wantRequests: 1},
		{name: "large blob is one request per chunk", size: 2*downloadChunkSize + 12345, wantRequests: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := make([]byte, tc.size)
			for i := range content {
				content[i] = byte(i * 7)
			}
			var requests atomic.Int32
			client := azureTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != "/ctr/obj" {
					http.NotFound(w, r)
					return
				}
				// Blob Storage takes the range as x-ms-range; ServeContent reads Range.
				r.Header.Set("Range", r.Header.Get("x-ms-range"))
				http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(content))
			}))
			rc, err := client.GetObject(context.Background(), "ctr", "obj")
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			got, err := io.ReadAll(rc)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, content) {
				t.Errorf("GetObject returned %d bytes that differ from the %d written", len(got), len(content))
			}
			if n := requests.Load(); n != tc.wantRequests {
				t.Errorf("server saw %d requests, want %d", n, tc.wantRequests)
			}
		})
	}
}
