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

package objectstorage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
)

// azureBlobClient stores objects in Azure Blob Storage. The client is bound to
// one storage account; a bucket names a container in it, so a snapshot
// location of any scheme (gs:// is what the GKE-shaped installers write)
// resolves to <account>/<container>/<object>.
type azureBlobClient struct {
	client *azblob.Client
}

// NewAzureBlobClient wraps a client bound to one storage account.
func NewAzureBlobClient(client *azblob.Client) ObjectStorage {
	return &azureBlobClient{client: client}
}

// NewAzureBlobClientFromEnv builds a client for the storage account named by
// AZURE_STORAGE_ACCOUNT, authenticated with the default Azure credential
// chain: on AKS that is the workload identity token projected into pods
// labeled azure.workload.identity/use.
func NewAzureBlobClientFromEnv(ctx context.Context) (*azblob.Client, error) {
	account := os.Getenv("AZURE_STORAGE_ACCOUNT")
	if account == "" {
		return nil, fmt.Errorf("AZURE_STORAGE_ACCOUNT must be set for the azblob storage backend")
	}
	slog.InfoContext(ctx, "Using Azure Blob storage backend", slog.String("account", account))
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("creating Azure credential: %w", err)
	}
	client, err := azblob.NewClient(fmt.Sprintf("https://%s.blob.core.windows.net/", account), cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating Azure Blob client: %w", err)
	}
	return client, nil
}

// supportsStreamingPut marks that PutObject accepts a non-seekable body: the
// SDK stages blocks from the stream itself. Never called: its presence is the
// signal.
func (a *azureBlobClient) supportsStreamingPut() {}

// PutObject writes reader to the blob as a single request below uploadPartSize
// and as parallel staged blocks above it, uploadConcurrency at a time.
func (a *azureBlobClient) PutObject(ctx context.Context, bucket, object string, reader io.Reader) error {
	_, err := a.client.UploadStream(ctx, bucket, object, reader, &azblob.UploadStreamOptions{
		BlockSize:   uploadPartSize,
		Concurrency: uploadConcurrency,
	})
	if err != nil {
		return fmt.Errorf("while putting blob: %w", err)
	}
	return nil
}

// GetObject streams the blob, fetching it as parallel byte ranges when it
// spans more than one chunk (see rangedget.go). The first chunk doubles as the
// size probe: Content-Range reports the whole blob's size.
func (a *azureBlobClient) GetObject(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
	head, err := a.client.DownloadStream(ctx, bucket, object, &azblob.DownloadStreamOptions{
		Range: blob.HTTPRange{Offset: 0, Count: downloadChunkSize},
	})
	if err != nil {
		if blobAbsent(err) {
			return nil, fmt.Errorf("%w: Failed to get Azure blob Container:%q, Blob:%q", ErrObjectNotFound, bucket, object)
		}
		return nil, err
	}
	size, ok := totalFromContentRange(head.ContentRange)
	if !ok {
		// No Content-Range: a server that ignored the range, so this is the
		// whole blob, and Content-Length, if set, is its size.
		if head.ContentLength == nil {
			return head.Body, nil
		}
		return &azureBody{ReadCloser: head.Body, size: *head.ContentLength}, nil
	}
	if size <= downloadChunkSize {
		return &azureBody{ReadCloser: head.Body, size: size}, nil
	}
	return newRangedReader(ctx, size, head.Body, a.fetchRange(bucket, object)), nil
}

// azureBody is a blob read in one request, whose size the response reported.
type azureBody struct {
	io.ReadCloser
	size int64
}

// ObjectSize implements SizedReader.
func (b *azureBody) ObjectSize() int64 { return b.size }

// fetchRange reads one range into buf.
func (a *azureBlobClient) fetchRange(bucket, object string) fetchRangeFunc {
	return func(ctx context.Context, _ int, off, n int64, buf []byte) error {
		out, err := a.client.DownloadStream(ctx, bucket, object, &azblob.DownloadStreamOptions{
			Range: blob.HTTPRange{Offset: off, Count: n},
		})
		if err != nil {
			return fmt.Errorf("while opening range %d+%d of %q: %w", off, n, object, err)
		}
		defer out.Body.Close()
		if _, err := io.ReadFull(out.Body, buf); err != nil {
			return fmt.Errorf("while reading range %d+%d of %q: %w", off, n, object, err)
		}
		return nil
	}
}

// blobAbsent reports whether the blob or container does not exist. A 403 is
// not absence, so a permission problem is not read as a missing snapshot.
func blobAbsent(err error) bool {
	if bloberror.HasCode(err, bloberror.BlobNotFound, bloberror.ContainerNotFound) {
		return true
	}
	var re *azcore.ResponseError
	if errors.As(err, &re) {
		return re.StatusCode == http.StatusNotFound
	}
	return false
}
