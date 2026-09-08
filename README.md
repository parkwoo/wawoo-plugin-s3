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

## Versioning, update & rollback

- **Compatible core**: wawoo-cms `>= 1.0.0`.
- **Pin a deployment**: record core + this plugin tags (e.g. both v1.0.0).

      git -C /path/to/wawoo-plugin-s3 checkout v1.0.0
      php bin/wawoo plugin:link /path/to/wawoo-plugin-s3

  Docker: use `--copy` (symlinks dangle in images):

      php bin/wawoo plugin:link /path/to/wawoo-plugin-s3 --copy

- **Configuration & persistent data**: **Credentials live in
  `cache/settings/s3.json`** (written by the admin Settings page: endpoint,
  region, bucket, access_key, secret_key, public_base, prefix, allow_http,
  rate_per_second). Treat that file as secret and back it up with the cache
  volume. No env vars. Requires openssl + TLS transports. SSRF/DNS-rebinding
  are enforced (public HTTPS only unless `allow_http`; connections pinned to
  the validated IP).
- **Before updating**: back up cache state volume + test:

      docker run --rm -v <cache-volume>:/data -v $PWD:/backup alpine tar czf /backup/cache.tgz -C /data .
      cd /path/to/wawoo-cms
      php bin/wawoo plugin:link /path/to/wawoo-plugin-s3
      phpunit tests/Plugin/S3*Test.php

- **Rollback**: checkout previous tag, re-link (--copy for Docker), restore cache volume backup, restart.

## License

Released under the [MIT License](LICENSE).

## Contributing & security

This is a standalone plugin/theme for [wawoo-cms](https://github.com/parkwoo/wawoo-cms).
Bugs, features and security reports follow the core project's policies:

- [CONTRIBUTING.md](https://github.com/parkwoo/wawoo-cms/blob/main/CONTRIBUTING.md)
- [SECURITY.md](https://github.com/parkwoo/wawoo-cms/blob/main/SECURITY.md)
- Versioning and rollback for this repository is described in the
  "Versioning, update & rollback" section above; releases are published as
  GitHub Releases on this repository's tags.
