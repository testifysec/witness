## witness verify

Verifies a witness policy

### Synopsis

Verifies a policy provided key source and exits with code 0 if verification succeeds

```
witness verify [flags]
```

### Options

```
  -f, --artifactfile string                 Path to the artifact to verify
      --attestation-digests strings         List of attestations in the form 'algorithm digest' for retrieval from archivist
  -a, --attestations strings                Attestation files to test against the policy
      --collector-ca-path string            Path to the collector server's certificate CA data
      --collector-client-cert-path string   Path to the collector client's certificate
      --collector-client-key-path string    Path to the collector client's private key
      --collector-server string             Collector server protocol and address (default "127.0.0.1:8080")
  -h, --help                                help for verify
  -p, --policy string                       Path to the policy to verify
      --policy-ca strings                   Paths to CA certificates to use for verifying the policy
  -k, --publickey string                    Path to the policy signer's public key
  -r, --rekor-server string                 Rekor server from which to fetch attestations
      --spiffe-server-id string             Sets allowed SPIFFE ID for dialing the server, defaults to any
      --spiffe-socket string                Path to the SPIFFE Workload API socket
```

### Options inherited from parent commands

```
  -c, --config string      Path to the witness config file (default ".witness.yaml")
  -l, --log-level string   Level of logging to output (debug, info, warn, error) (default "info")
```

### SEE ALSO

* [witness](witness.md)	 - Collect and verify attestations about your build environments

