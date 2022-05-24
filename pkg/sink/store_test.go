// Copyright 2021 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sink

import (
	"context"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/stretchr/testify/assert"
	"github.com/testifysec/archivist-api/pkg/api/archivist"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
	"net/url"
	"path/filepath"
	"testing"
)

type testCollectorServer struct {
	archivist.UnimplementedCollectorServer
	test    *testing.T
	context context.Context
}

func newTestServer(t *testing.T, ctx context.Context) archivist.CollectorServer {
	return &testCollectorServer{
		test:    t,
		context: ctx,
	}
}

type ctxKey string

func (s *testCollectorServer) Store(_ context.Context, request *archivist.StoreRequest) (*emptypb.Empty, error) {
	assert.Equal(s.test, s.context.Value(ctxKey("envelope")), request.Object)
	return &emptypb.Empty{}, nil
}

func TestInsecureSink(t *testing.T) {
	grpcOptions := make([]grpc.ServerOption, 0)
	grpcOptions = append(grpcOptions, grpc.Creds(insecure.NewCredentials()))
	grpcServer := grpc.NewServer(grpcOptions...)

	testValue := "test"
	ctx := context.WithValue(context.Background(), ctxKey("envelope"), testValue)
	collectorService := newTestServer(t, ctx)
	archivist.RegisterCollectorServer(grpcServer, collectorService)

	hostUrl, _ := url.Parse("tcp://127.0.0.1:9090")
	grpcutils.ListenAndServe(ctx, hostUrl, grpcServer)

	sink, _ := NewCollector("127.0.0.1:9090", "", "", "", "", "")
	if err := sink.Store(testValue, ctx); err != nil {
		t.Errorf("failed to store attestation during test: %v", err)
	}
}

func TestTlsSink(t *testing.T) {
	creds, err := credentials.NewServerTLSFromFile(
		filepath.Join("testdata", "server-cert.pem"),
		filepath.Join("testdata", "server-key.pem"),
	)
	if err != nil {
		t.Errorf("could not load server TLS for test: %v", err)
	}

	grpcOptions := []grpc.ServerOption{grpc.Creds(creds)}
	grpcServer := grpc.NewServer(grpcOptions...)

	testValue := "test"
	ctx := context.WithValue(context.Background(), ctxKey("envelope"), testValue)
	collectorService := newTestServer(t, ctx)
	archivist.RegisterCollectorServer(grpcServer, collectorService)

	hostUrl, _ := url.Parse("tcp://127.0.0.1:9091")
	grpcutils.ListenAndServe(ctx, hostUrl, grpcServer)

	sink, _ := NewCollector("127.0.0.1:9091", filepath.Join("testdata", "ca-cert.pem"),
		"", "", "", "")
	if err := sink.Store(testValue, ctx); err != nil {
		t.Errorf("failed to store attestation during test: %v", err)
	}
}
