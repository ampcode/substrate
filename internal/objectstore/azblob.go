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

package objectstore

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
)

// azureCopyPollInterval is how often a pending server-side copy is checked on.
// Copies within one storage account usually finish before the first check.
const azureCopyPollInterval = time.Second

type azureBlobStore struct {
	client *azblob.Client
}

// NewAzureBlob returns a Store backed by Azure Blob Storage. The client is
// bound to one storage account; a bucket names a container in it.
func NewAzureBlob(client *azblob.Client) Store {
	return &azureBlobStore{client: client}
}

func (a *azureBlobStore) List(ctx context.Context, bucket, prefix string) ([]string, error) {
	pager := a.client.NewListBlobsFlatPager(bucket, &azblob.ListBlobsFlatOptions{Prefix: &prefix})
	var objects []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("while listing blobs under %s/%s: %w", bucket, prefix, err)
		}
		if page.Segment == nil {
			continue
		}
		for _, item := range page.Segment.BlobItems {
			if item.Name != nil {
				objects = append(objects, *item.Name)
			}
		}
	}
	return objects, nil
}

func (a *azureBlobStore) Delete(ctx context.Context, bucket, object string) error {
	_, err := a.client.DeleteBlob(ctx, bucket, object, nil)
	// A blob that is already gone is the state this asks for.
	if err != nil && !bloberror.HasCode(err, bloberror.BlobNotFound) {
		return fmt.Errorf("while deleting %s/%s: %w", bucket, object, err)
	}
	return nil
}

// Copy runs a server-side copy. Copy Blob is asynchronous, so this waits for
// the copy to leave the pending state; the bytes move inside the storage
// account whatever the blob's size. The source is in the same account, so the
// request's own credential authorizes reading it.
func (a *azureBlobStore) Copy(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject string) error {
	svc := a.client.ServiceClient()
	src := svc.NewContainerClient(srcBucket).NewBlobClient(srcObject)
	dst := svc.NewContainerClient(dstBucket).NewBlobClient(dstObject)
	started, err := dst.StartCopyFromURL(ctx, src.URL(), nil)
	if err != nil {
		return fmt.Errorf("while copying %s/%s to %s/%s: %w", srcBucket, srcObject, dstBucket, dstObject, err)
	}
	status := started.CopyStatus
	for status != nil && *status == blob.CopyStatusTypePending {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(azureCopyPollInterval):
		}
		props, err := dst.GetProperties(ctx, nil)
		if err != nil {
			return fmt.Errorf("while waiting for copy to %s/%s: %w", dstBucket, dstObject, err)
		}
		status = props.CopyStatus
	}
	if status != nil && *status != blob.CopyStatusTypeSuccess {
		return fmt.Errorf("copy of %s/%s to %s/%s ended with status %q", srcBucket, srcObject, dstBucket, dstObject, *status)
	}
	return nil
}
