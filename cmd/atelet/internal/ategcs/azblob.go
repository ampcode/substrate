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
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
)

// azureBlobClient stores objects in Azure Blob Storage. A gs://<bucket>/<object>
// URL names the container <bucket> in the storage account the client was built for.
type azureBlobClient struct {
	client *azblob.Client
}

// NewAzureBlobClient wraps a client bound to one storage account.
func NewAzureBlobClient(client *azblob.Client) ObjectStorage {
	return &azureBlobClient{client: client}
}

// supportsStreamingPut marks that PutObject accepts a non-seekable body.
func (a *azureBlobClient) supportsStreamingPut() {}

// PutObject writes reader to the blob as a single request below uploadPartSize and
// as parallel staged blocks above it, uploadConcurrency at a time.
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

// GetObject streams the blob, fetching it as parallel byte ranges when it spans more
// than one chunk (see rangedget.go). The first chunk doubles as the size probe.
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
	if !ok || size <= downloadChunkSize {
		return head.Body, nil
	}
	return newRangedReader(ctx, size, head.Body, a.fetchRange(bucket, object)), nil
}

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

// blobAbsent reports whether the blob or container does not exist. A 403 is not
// absence, so a permission problem is not read as a missing snapshot.
func blobAbsent(err error) bool {
	if bloberror.HasCode(err, bloberror.BlobNotFound, bloberror.ContainerNotFound) {
		return true
	}
	if re, ok := errors.AsType[*azcore.ResponseError](err); ok {
		return re.StatusCode == http.StatusNotFound
	}
	return false
}
