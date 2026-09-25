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

package objectstore_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/agent-substrate/substrate/internal/objectstore"
	"github.com/google/go-cmp/cmp"
)

// azureRequest is one call the SDK made, reduced to what the tests assert on.
type azureRequest struct {
	method     string
	path       string
	comp       string
	prefix     string
	copySource string
}

// fakeAzure serves canned responses over HTTP so the SDK does real request
// building and response parsing, and records what it was asked for.
type fakeAzure struct {
	// handle, when set, answers a request before the default handling and
	// reports whether it did.
	handle func(w http.ResponseWriter, r *http.Request) bool

	mu       sync.Mutex
	requests []azureRequest
}

// newAzure starts a fake blob service and returns it with a Store pointed at it.
func newAzure(t *testing.T) (*fakeAzure, objectstore.Store) {
	t.Helper()
	fake := &fakeAzure{}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	client, err := azblob.NewClientWithNoCredential(srv.URL+"/", &azblob.ClientOptions{
		ClientOptions: policy.ClientOptions{
			// Disable retry backoff to keep tests fast.
			Retry: policy.RetryOptions{MaxRetries: -1},
		},
	})
	if err != nil {
		t.Fatalf("azblob client: %v", err)
	}
	return fake, objectstore.NewAzureBlob(client)
}

func (f *fakeAzure) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	f.mu.Lock()
	f.requests = append(f.requests, azureRequest{
		method:     r.Method,
		path:       r.URL.Path,
		comp:       query.Get("comp"),
		prefix:     query.Get("prefix"),
		copySource: r.Header.Get("x-ms-copy-source"),
	})
	f.mu.Unlock()

	if f.handle != nil && f.handle(w, r) {
		return
	}
	switch {
	case r.Method == http.MethodPut && r.Header.Get("x-ms-copy-source") != "":
		w.Header().Set("x-ms-copy-status", "success")
		w.WriteHeader(http.StatusAccepted)
	case r.Method == http.MethodDelete:
		w.WriteHeader(http.StatusAccepted)
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func (f *fakeAzure) requestsSeen() []azureRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

// TestAzureBlobList covers a listing that spans pages: every page's names are
// returned, in order, and the second page is asked for with the first's marker.
func TestAzureBlobList(t *testing.T) {
	fake, store := newAzure(t)
	fake.handle = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Query().Get("comp") != "list" {
			return false
		}
		w.Header().Set("Content-Type", "application/xml")
		if r.URL.Query().Get("marker") == "" {
			writeXML(w, `<EnumerationResults ServiceEndpoint="http://example/" ContainerName="bucket">
				<Prefix>root/snap/</Prefix>
				<Blobs>
					<Blob><Name>root/snap/manifest.json</Name></Blob>
					<Blob><Name>root/snap/memory.zst</Name></Blob>
				</Blobs>
				<NextMarker>page-2</NextMarker>
			</EnumerationResults>`)
			return true
		}
		writeXML(w, `<EnumerationResults ServiceEndpoint="http://example/" ContainerName="bucket">
			<Prefix>root/snap/</Prefix>
			<Blobs>
				<Blob><Name>root/snap/rootfs.zst</Name></Blob>
			</Blobs>
			<NextMarker/>
		</EnumerationResults>`)
		return true
	}

	objects, err := store.List(t.Context(), "bucket", "root/snap/")
	if err != nil {
		t.Fatalf("List() = %v, want nil", err)
	}
	want := []string{"root/snap/manifest.json", "root/snap/memory.zst", "root/snap/rootfs.zst"}
	if diff := cmp.Diff(want, objects); diff != "" {
		t.Errorf("List() differs (-want +got):\n%s", diff)
	}
	wantRequests := []azureRequest{
		{method: http.MethodGet, path: "/bucket", comp: "list", prefix: "root/snap/"},
		{method: http.MethodGet, path: "/bucket", comp: "list", prefix: "root/snap/"},
	}
	if diff := cmp.Diff(wantRequests, fake.requestsSeen(), cmp.AllowUnexported(azureRequest{})); diff != "" {
		t.Errorf("requests differ (-want +got):\n%s", diff)
	}
}

func TestAzureBlobDelete(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		code    string
		wantErr bool
	}{
		{
			name:   "deleted",
			status: http.StatusAccepted,
		},
		{
			name:   "already gone",
			status: http.StatusNotFound,
			code:   "BlobNotFound",
		},
		{
			// A missing container is not the state a delete asks for: the
			// snapshot's blobs may well exist somewhere this cannot see.
			name:    "container missing",
			status:  http.StatusNotFound,
			code:    "ContainerNotFound",
			wantErr: true,
		},
		{
			name:    "forbidden",
			status:  http.StatusForbidden,
			code:    "AuthorizationPermissionMismatch",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake, store := newAzure(t)
			fake.handle = func(w http.ResponseWriter, _ *http.Request) bool {
				if tt.code != "" {
					w.Header().Set("x-ms-error-code", tt.code)
				}
				w.WriteHeader(tt.status)
				return true
			}

			err := store.Delete(t.Context(), "bucket", "root/snap/memory.zst")
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("Delete() = %v, want an error: %v", err, tt.wantErr)
			}
			want := []azureRequest{{method: http.MethodDelete, path: "/bucket/root/snap/memory.zst"}}
			if diff := cmp.Diff(want, fake.requestsSeen(), cmp.AllowUnexported(azureRequest{})); diff != "" {
				t.Errorf("requests differ (-want +got):\n%s", diff)
			}
		})
	}
}

// TestAzureBlobCopy covers a copy the service completes synchronously: one
// Copy Blob request naming the source, and no polling.
func TestAzureBlobCopy(t *testing.T) {
	fake, store := newAzure(t)

	if err := store.Copy(t.Context(), "src-bucket", "root/snap/memory.zst", "dst-bucket", "root/tag-v1/memory.zst"); err != nil {
		t.Fatalf("Copy() = %v, want nil", err)
	}
	got := fake.requestsSeen()
	if len(got) != 1 {
		t.Fatalf("Copy() made %d requests, want 1: %+v", len(got), got)
	}
	if got[0].method != http.MethodPut || got[0].path != "/dst-bucket/root/tag-v1/memory.zst" {
		t.Errorf("Copy() request = %s %s, want PUT /dst-bucket/root/tag-v1/memory.zst", got[0].method, got[0].path)
	}
	source, err := url.Parse(got[0].copySource)
	if err != nil || source.Path != "/src-bucket/root/snap/memory.zst" {
		t.Errorf("Copy() x-ms-copy-source = %q, want the source blob's URL", got[0].copySource)
	}
}

// TestAzureBlobCopyPending covers an asynchronous copy: the destination's
// properties are polled until the copy leaves the pending state, and a copy
// the service reports as failed is an error.
func TestAzureBlobCopyPending(t *testing.T) {
	tests := []struct {
		name    string
		final   string
		wantErr bool
	}{
		{name: "succeeds", final: "success"},
		{name: "fails", final: "failed", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake, store := newAzure(t)
			polls := 0
			fake.handle = func(w http.ResponseWriter, r *http.Request) bool {
				switch {
				case r.Method == http.MethodPut:
					w.Header().Set("x-ms-copy-status", "pending")
					w.WriteHeader(http.StatusAccepted)
				case r.Method == http.MethodHead:
					polls++
					status := "pending"
					if polls >= 2 {
						status = tt.final
					}
					w.Header().Set("x-ms-copy-status", status)
					w.Header().Set("Content-Length", "0")
					w.WriteHeader(http.StatusOK)
				default:
					return false
				}
				return true
			}

			err := store.Copy(t.Context(), "bucket", "root/snap/memory.zst", "bucket", "root/tag-v1/memory.zst")
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("Copy() = %v, want an error: %v", err, tt.wantErr)
			}
			if polls != 2 {
				t.Errorf("Copy() polled %d times, want 2", polls)
			}
		})
	}
}
