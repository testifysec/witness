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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	api "github.com/testifysec/archivist-api/pkg/api/archivist"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"io/ioutil"
)

type sink struct {
	conn      *grpc.ClientConn
	collector api.CollectorClient
	archivist api.ArchivistClient
}

type Archivist interface {
	GetBySubjectDigestRequest(ctx context.Context, algorithm, digest string) ([]string, error)
}

type Collector interface {
	Store(attestation string, ctx context.Context) error
}

// NewCollector returns a new collector sink client to store attestations generated by Witness.
func NewCollector(addr, caPath, clientCertPath, clientKeyPath, spiffeAddress, spiffeServerId string) (Collector, error) {
	opts, err := setDialOpts(caPath, clientCertPath, clientKeyPath, spiffeAddress, spiffeServerId)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, err
	}
	return &sink{
		collector: api.NewCollectorClient(conn),
		conn:      conn,
	}, nil
}

// NewArchivist returns a new archivist sink client to retrieve attestations generated by Witness for verification.
func NewArchivist(addr, caPath, clientCertPath, clientKeyPath, spiffeAddress, spiffeServerId string) (Archivist, error) {
	opts, err := setDialOpts(caPath, clientCertPath, clientKeyPath, spiffeAddress, spiffeServerId)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, err
	}
	return &sink{
		archivist: api.NewArchivistClient(conn),
		conn:      conn,
	}, nil
}

// set dial options to use no authentication, TLS for server CA, or mutual auth for shared CA
func setDialOpts(caPath, clientCertPath, clientKeyPath, spiffeAddress, spiffeServerId string) ([]grpc.DialOption, error) {
	dialOpts := make([]grpc.DialOption, 0)

	if spiffeAddress != "" {
		workloadOpts := []workloadapi.ClientOption{
			workloadapi.WithAddr(spiffeAddress),
		}
		svidSource, err := workloadapi.NewX509Source(
			context.Background(),
			workloadapi.WithClientOptions(workloadOpts...),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to connect to spire workload api: %v", err)
		}

		var authorizer tlsconfig.Authorizer
		if spiffeServerId != "" {
			authorizer = tlsconfig.AuthorizeID(spiffeid.RequireFromString(spiffeServerId))
		} else {
			authorizer = tlsconfig.AuthorizeAny()
		}

		creds := grpccredentials.MTLSClientCredentials(svidSource, svidSource, authorizer)
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))

	} else if caPath != "" {
		caFile, err := ioutil.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caFile) {
			return nil, fmt.Errorf("failed to load collector CA into pool: %v", err)
		}
		cfg := &tls.Config{RootCAs: pool}

		if clientCertPath != "" {
			cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load client cert: %v", err)
			}
			cfg.Certificates = []tls.Certificate{cert}
		}

		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))

	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	return dialOpts, nil
}

// Store the attestation generated by Witness.
func (s *sink) Store(attestation string, ctx context.Context) error {
	r := api.StoreRequest{Object: attestation}
	_, err := s.collector.Store(ctx, &r)
	return err
}

// GetBySubjectDigestRequest retrieves an attestation generated by Witness from the backend archivist store.
func (s *sink) GetBySubjectDigestRequest(ctx context.Context, algorithm, digest string) ([]string, error) {
	r := api.GetBySubjectDigestRequest{
		Algorithm: algorithm,
		Value:     digest,
	}
	resp, err := s.archivist.GetBySubjectDigest(ctx, &r)
	return resp.Object, err
}

// Stop the sink client and terminate its connection gracefully.
func (s *sink) Stop() error {
	return s.conn.Close()
}
