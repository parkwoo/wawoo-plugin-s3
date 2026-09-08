# wawoo-plugin-s3

Mirrors content media to S3-compatible object storage via a minimal AWS Signature Version 4 client and rewrites media URLs to the storage public base.

## Install

```
cd /path/to/wawoo-cms
php bin/wawoo plugin:link /home/git/wawoo-plugin-s3
```

Enable via config.local.php ENABLED_PLUGINS or admin Plugins page.

## Test (testing contract)

```
cd /path/to/wawoo-cms
php bin/wawoo plugin:link /home/git/wawoo-plugin-s3
phpunit tests/Plugin/S3*Test.php
```

## Requirements

`wawoo-cms >= 1.0.0`, PHP 8.3, no runtime deps.

Runtime notes:

- Needs openssl and TLS transports (manual pinned-IP sockets, no curl or
  third-party SDKs). Plain http is only possible behind the explicit
  `allow_http` flag.
- Optional `rate_per_second` config throttles sync uploads.
- Endpoint validation and pinned addresses make the client SSRF- and
  DNS-rebinding-resistant: the host is validated once in the constructor,
  verified public addresses are pinned, and DNS is never re-consulted at
  connect time.

## CI

GitHub Actions runs on PHP 8.2 & 8.3 — it clones wawoo-cms core, links this plugin via `php bin/wawoo plugin:link --copy`, and runs `phpunit tests/Plugin/S3*Test.php`.

## Dependencies

Requires core outbound rate limiter availability (`Wawoo\Core\RateLimit`, core >=1.0.0), openssl + TLS transports. Optional `rate_per_second` config. No cross-plugin dependency.

## Release

Manifests require `core >=1.0.0`; this repo is tagged `v1.0.0`; bump manifest + tag together on releases.
