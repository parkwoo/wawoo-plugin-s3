<?php
namespace Wawoo\Plugin\S3;

/**
 * Minimal AWS Signature Version 4 client for S3-compatible object storage.
 *
 * Talks to the configured endpoint using a manual pinned-IP socket (no curl,
 * no third-party SDKs, no http stream wrapper). The endpoint host is validated
 * once in the constructor and the verified public addresses are pinned; every
 * request connects straight to a pinned IP so DNS is never re-consulted at
 * connect time (DNS-rebinding resistant). TLS certificate and SNI verification
 * still run against the original hostname via peer_name. Requests are signed
 * for path-style access (endpoint/bucket/key), which AWS S3, Cloudflare R2
 * and MinIO all accept.
 */
final class Client
{
    private array $cfg;
    private ?string $scheme = null;
    private ?string $pinnedHost = null;
    private ?array $pinnedIps = null;
    private ?int $port = null;

    public function __construct(array $cfg = [])
    {
        $this->cfg = $cfg;
        $endpoint = trim((string)($cfg['endpoint'] ?? ''));
        $clean = $endpoint !== '' ? self::validateEndpoint($endpoint, $cfg) : null;
        if ($clean === null) {
            return;
        }
        $split = self::splitEndpoint($clean);
        if ($split === null) {
            return;
        }
        [$scheme, $host, $port] = $split;
        $bare = trim($host, '[]');
        $this->scheme = $scheme;
        $this->port = $port ?? ($scheme === 'http' ? 80 : 443);
        $this->pinnedHost = $bare;
        $this->pinnedIps = filter_var($bare, FILTER_VALIDATE_IP) !== false
            ? [$bare]
            : self::resolvePinnedAddresses($bare);
    }

    /** First verified public address requests connect to, or null. */
    public function pinnedIp(): ?string
    {
        return $this->pinnedIps[0] ?? null;
    }

    /** Hostname (or literal IP) TLS verification and Host headers use. */
    public function pinnedHost(): ?string
    {
        return $this->pinnedHost;
    }

    /**
     * Structurally split an endpoint URL into [scheme, host, port] where port
     * is null when absent. No DNS or SSRF checks happen here.
     */
    public static function splitEndpoint(string $endpoint): ?array
    {
        $endpoint = trim($endpoint);
        if ($endpoint === '' || !preg_match('#^https?://#i', $endpoint)) {
            return null;
        }
        $parts = parse_url($endpoint);
        if ($parts === false || !isset($parts['host'])) {
            return null;
        }
        $scheme = strtolower((string)$parts['scheme']);
        if ($scheme !== 'https' && $scheme !== 'http') {
            return null;
        }
        $host = (string)$parts['host'];
        if ($host === '' || isset($parts['user']) || isset($parts['pass'])) {
            return null;
        }
        $path = (string)($parts['path'] ?? '');
        if (trim($path, '/') !== '' || isset($parts['query']) || isset($parts['fragment'])) {
            return null;
        }
        $port = isset($parts['port']) ? (int)$parts['port'] : null;
        if ($port !== null && ($port < 1 || $port > 65535)) {
            return null;
        }
        return [$scheme, $host, $port];
    }

    /**
     * Normalize and SSRF-validate an S3 endpoint. Returns the cleaned
     * scheme://host[:port] string when the host only resolves to public
     * addresses, or null when the endpoint is unusable (http without
     * allow_http, embedded path/userinfo, blocked port, or any resolved
     * loopback/private/link-local/unspecified address).
     */
    public static function validateEndpoint(string $endpoint, array $cfg = []): ?string
    {
        $split = self::splitEndpoint($endpoint);
        if ($split === null) {
            return null;
        }
        [$scheme, $host, $port] = $split;
        $allowHttp = !empty($cfg['allow_http']);
        if ($scheme === 'http' && !$allowHttp) {
            return null;
        }
        if ($port !== null && !self::portAllowed($scheme, $port, $allowHttp)) {
            return null;
        }
        $addresses = self::hostAddresses($host);
        if ($addresses === [] && filter_var($host, FILTER_VALIDATE_IP) === false) {
            return null; // unresolvable host — fail closed (also network-free)
        }
        foreach ($addresses as $address) {
            if (self::isBlockedAddress($address)) {
                return null;
            }
        }
        return self::buildEndpoint($scheme, $host, $port);
    }

    /**
     * Resolve a hostname to the verified public addresses requests may pin.
     * Returns a non-empty list of public IP strings, or null when the host is
     * a blocked literal, resolves to no public address, or cannot be resolved.
     */
    public static function resolvePinnedAddresses(string $host): ?array
    {
        $pinned = [];
        foreach (self::hostAddresses($host) as $address) {
            if (!self::isBlockedAddress($address)) {
                $pinned[] = $address;
            }
        }
        $pinned = array_values(array_unique($pinned));
        return $pinned !== [] ? $pinned : null;
    }

    private static function portAllowed(string $scheme, int $port, bool $allowHttp): bool
    {
        if ($allowHttp) {
            return $port > 0 && $port <= 65535;
        }
        return $scheme === 'https' && ($port === 443 || $port === 8443);
    }

    /**
     * Optional DNS resolver override for tests: fn(string $host): array of
     * address strings. Null (default) uses the system resolver.
     * @var (callable(string):array)|null
     */
    public static $resolver = null;

    private static function hostAddresses(string $host): array
    {
        $host = trim($host, '[]');
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }
        if (self::$resolver !== null) {
            $out = (self::$resolver)($host);
            return is_array($out) ? array_values(array_filter($out, 'is_string')) : [];
        }
        $addresses = [];
        $ipv4 = gethostbynamel($host);
        if (is_array($ipv4)) {
            $addresses = $ipv4;
        }
        $aaaa = @dns_get_record($host, DNS_AAAA);
        if (is_array($aaaa)) {
            foreach ($aaaa as $record) {
                if (isset($record['ipv6'])) {
                    $addresses[] = $record['ipv6'];
                }
            }
        }
        return $addresses;
    }

    private static function isBlockedAddress(string $address): bool
    {
        $bin = @inet_pton($address);
        if ($bin === false) {
            return true;
        }
        if (strlen($bin) === 4) {
            [$b1, $b2, $b3] = array_values(unpack('C4', $bin));
            if ($b1 === 0 || $b1 === 127) {
                return true;
            }
            if ($b1 === 10) {
                return true;
            }
            if ($b1 === 100 && $b2 >= 64 && $b2 <= 127) {
                return true;
            }
            if ($b1 === 169 && $b2 === 254) {
                return true;
            }
            if ($b1 === 172 && $b2 >= 16 && $b2 <= 31) {
                return true;
            }
            if ($b1 === 192 && $b2 === 168) {
                return true;
            }
            if ($b1 === 192 && $b2 === 0 && ($b3 === 0 || $b3 === 2)) {
                return true;
            }
            if ($b1 === 198 && ($b2 === 18 || $b2 === 19)) {
                return true;
            }
            if (($b1 === 198 && $b2 === 51 && $b3 === 100) || ($b1 === 203 && $b2 === 0 && $b3 === 113)) {
                return true;
            }
            if ($b1 >= 224) {
                return true;
            }
            return false;
        }
        if (strlen($bin) === 16) {
            $w = array_values(unpack('n8', $bin));
            if ($w[0] === 0 && $w[1] === 0 && $w[2] === 0 && $w[3] === 0 && $w[4] === 0 && $w[5] === 0xffff) {
                return self::isBlockedAddress(inet_ntop(pack('N', ($w[6] << 16) | $w[7])));
            }
            if ($w[0] === 0 && $w[1] === 0 && $w[2] === 0 && $w[3] === 0 && $w[4] === 0 && $w[5] === 0 && $w[6] === 0) {
                return $w[7] === 0 || $w[7] === 1;
            }
            if (($w[0] & 0xffc0) === 0xfe80) {
                return true;
            }
            if (($w[0] & 0xfe00) === 0xfc00) {
                return true;
            }
            if (($w[0] & 0xff00) === 0xff00) {
                return true;
            }
            return false;
        }
        return true;
    }

    private static function buildEndpoint(string $scheme, string $host, ?int $port): string
    {
        $bare = trim($host, '[]');
        $authority = str_contains($bare, ':') ? '[' . $bare . ']' : $bare;
        return $scheme . '://' . $authority . ($port !== null ? ':' . $port : '');
    }

    public static function region(array $cfg): string
    {
        $region = trim((string)($cfg['region'] ?? ''));
        return $region !== '' ? $region : 'us-east-1';
    }

    public static function hmacSha256(string $key, string $data): string
    {
        return hash_hmac('sha256', $data, $key, true);
    }

    /**
     * Derive the SigV4 signing key (binary) for a scope of
     * dateStamp/region/service/aws4_request.
     */
    public static function signingKey(string $secret, string $dateStamp, string $region, string $service): string
    {
        $k = self::hmacSha256('AWS4' . $secret, $dateStamp);
        $k = self::hmacSha256($k, $region);
        $k = self::hmacSha256($k, $service);
        return self::hmacSha256($k, 'aws4_request');
    }

    /**
     * The canonical request string for SigV4. $headers maps header name to
     * value; names are lowercased and sorted, and the sorted names become
     * the trailing SignedHeaders line.
     */
    public static function canonicalRequest(
        string $method,
        string $canonicalUri,
        string $canonicalQuery,
        array $headers,
        string $payloadHash
    ): string {
        $headers = self::normalizedHeaders($headers);
        ksort($headers);
        $lines = '';
        foreach ($headers as $name => $value) {
            $lines .= $name . ':' . trim($value) . "\n";
        }
        $signed = implode(';', array_keys($headers));
        return $method . "\n"
            . $canonicalUri . "\n"
            . $canonicalQuery . "\n"
            . $lines
            . "\n"
            . $signed . "\n"
            . $payloadHash;
    }

    public static function stringToSign(string $amzDate, string $scope, string $canonicalRequest): string
    {
        return "AWS4-HMAC-SHA256\n" . $amzDate . "\n" . $scope . "\n" . hash('sha256', $canonicalRequest);
    }

    public static function contentTypeFor(string $path): string
    {
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        $map = [
            'png'   => 'image/png',
            'jpg'   => 'image/jpeg',
            'jpeg'  => 'image/jpeg',
            'gif'   => 'image/gif',
            'svg'   => 'image/svg+xml',
            'webp'  => 'image/webp',
            'avif'  => 'image/avif',
            'ico'   => 'image/x-icon',
            'pdf'   => 'application/pdf',
            'mp4'   => 'video/mp4',
            'webm'  => 'video/webm',
            'mp3'   => 'audio/mpeg',
            'wav'   => 'audio/wav',
            'ogg'   => 'audio/ogg',
            'css'   => 'text/css',
            'js'    => 'application/javascript',
            'json'  => 'application/json',
            'txt'   => 'text/plain',
            'woff'  => 'font/woff',
            'woff2' => 'font/woff2',
            'ttf'   => 'font/ttf',
        ];
        return $map[$ext] ?? 'application/octet-stream';
    }

    public function putObject(string $key, string $body, string $contentType): bool
    {
        [$status] = $this->request('PUT', $key, $body, $contentType);
        return $status >= 200 && $status < 300;
    }

    /** Create the configured bucket if missing (path-style PUT /bucket/). */
    public function putBucket(): bool
    {
        [$status] = $this->request('PUT', '', '');
        return $status >= 200 && $status < 300;
    }

    public function objectExists(string $key): bool
    {
        [$status] = $this->request('HEAD', $key);
        return $status === 200;
    }

    public function deleteObject(string $key): bool
    {
        [$status] = $this->request('DELETE', $key);
        return $status >= 200 && $status < 300;
    }

    /**
     * Perform one signed request against the pinned endpoint and return
     * [httpStatus, responseBody]. The connection goes to the address pinned in
     * the constructor (never a fresh DNS lookup) and TLS verifies against the
     * original hostname. Non-2xx responses are still read back so the caller
     * can decide.
     */
    private function request(string $method, string $key, string $body = '', ?string $contentType = null): array
    {
        if ($this->pinnedHost === null || $this->pinnedIps === null || $this->pinnedIps === []) {
            return [0, ''];
        }
        $bucket = trim((string)($this->cfg['bucket'] ?? ''));
        $access = (string)($this->cfg['access_key'] ?? '');
        $secret = (string)($this->cfg['secret_key'] ?? '');
        if ($bucket === '' || $access === '' || $secret === '') {
            return [0, ''];
        }

        // Optional per-second cap shared across outbound clients. Off by
        // default (rate_per_second <= 0 = unlimited); when set, the value is
        // used as-is via Wawoo\Core\RateLimit.
        $rate = isset($this->cfg['rate_per_second']) ? (int)$this->cfg['rate_per_second'] : 0;
        if ($rate > 0 && !\Wawoo\Core\RateLimit::allow('outbound', $rate)) {
            return [429, ''];
        }

        $region = self::region($this->cfg);
        $uri = '/' . self::encodePath($bucket) . '/' . self::encodePath($key);
        $amzDate = gmdate('Ymd\THis\Z');
        $dateStamp = gmdate('Ymd');
        $payloadHash = hash('sha256', $body);

        $host = $this->hostHeader();
        $headers = [
            'host'                 => $host,
            'x-amz-content-sha256' => $payloadHash,
            'x-amz-date'           => $amzDate,
        ];
        if ($contentType !== null && $contentType !== '') {
            $headers['content-type'] = $contentType;
        }

        $canonical = self::canonicalRequest($method, $uri, '', $headers, $payloadHash);
        $signedHeaders = self::signedHeaderNames($headers);
        $scope = $dateStamp . '/' . $region . '/s3/aws4_request';
        $signature = hash_hmac(
            'sha256',
            self::stringToSign($amzDate, $scope, $canonical),
            self::signingKey($secret, $dateStamp, $region, 's3')
        );
        $authorization = 'AWS4-HMAC-SHA256 Credential=' . $access . '/' . $scope
            . ', SignedHeaders=' . $signedHeaders
            . ', Signature=' . $signature;

        $raw = $method . ' ' . $uri . " HTTP/1.1\r\n"
            . 'Host: ' . $host . "\r\n"
            . 'x-amz-date: ' . $amzDate . "\r\n"
            . 'x-amz-content-sha256: ' . $payloadHash . "\r\n"
            . 'Authorization: ' . $authorization . "\r\n";
        if (isset($headers['content-type'])) {
            $raw .= 'Content-Type: ' . $headers['content-type'] . "\r\n";
        }
        $raw .= 'Content-Length: ' . strlen($body) . "\r\n"
            . "Connection: close\r\n\r\n"
            . $body;

        return $this->transact($raw);
    }

    /**
     * Open a raw TCP socket to a pinned IP, enable TLS against the original
     * hostname when https, write the request and read the response to EOF.
     */
    private function transact(string $request): array
    {
        $ip = $this->pinnedIps[0];
        $target = str_contains($ip, ':') ? '[' . $ip . ']' : $ip;
        $ctx = stream_context_create(['ssl' => [
            'peer_name'        => (string)$this->pinnedHost,
            'SNI_enabled'      => true,
            'verify_peer'      => true,
            'verify_peer_name' => true,
        ]]);
        $sock = @stream_socket_client(
            'tcp://' . $target . ':' . $this->port,
            $errno,
            $errstr,
            30,
            STREAM_CLIENT_CONNECT,
            $ctx
        );
        if ($sock === false) {
            return [0, ''];
        }
        if ($this->scheme === 'https') {
            $tls = @stream_socket_enable_crypto(
                $sock,
                true,
                STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT
            );
            if ($tls !== true) {
                fclose($sock);
                return [0, ''];
            }
        }
        stream_set_timeout($sock, 30);
        self::writeAll($sock, $request);
        $data = self::readAll($sock);
        fclose($sock);
        return self::parseResponse($data);
    }

    private function hostHeader(): string
    {
        $host = (string)$this->pinnedHost;
        if (filter_var($host, FILTER_VALIDATE_IP) !== false && str_contains($host, ':')) {
            $host = '[' . $host . ']';
        }
        $default = $this->scheme === 'http' ? 80 : 443;
        if ($this->port !== null && $this->port !== $default) {
            $host .= ':' . $this->port;
        }
        return $host;
    }

    private static function writeAll($sock, string $data): void
    {
        $total = strlen($data);
        $offset = 0;
        while ($offset < $total) {
            $written = @fwrite($sock, $offset === 0 ? $data : substr($data, $offset));
            if ($written === false || $written === 0) {
                return;
            }
            $offset += $written;
        }
    }

    private static function readAll($sock): string
    {
        $data = '';
        while (!feof($sock)) {
            $chunk = @fread($sock, 16384);
            if ($chunk === false) {
                break;
            }
            if ($chunk === '') {
                if (!empty(stream_get_meta_data($sock)['timed_out'])) {
                    break;
                }
                continue;
            }
            $data .= $chunk;
        }
        return $data;
    }

    /** Split head/body, extract the status code and de-chunk when needed. */
    private static function parseResponse(string $data): array
    {
        $head = $data;
        $body = '';
        $sep = strpos($data, "\r\n\r\n");
        if ($sep !== false) {
            $head = substr($data, 0, $sep);
            $body = substr($data, $sep + 4);
        } else {
            $sep = strpos($data, "\n\n");
            if ($sep !== false) {
                $head = substr($data, 0, $sep);
                $body = substr($data, $sep + 2);
            }
        }
        $lines = preg_split("/\r\n|\r|\n/", $head) ?: [];
        $status = 0;
        if (isset($lines[0]) && preg_match('#^HTTP/\S+\s+(\d{3})#', $lines[0], $m)) {
            $status = (int)$m[1];
        }
        $chunked = false;
        foreach (array_slice($lines, 1) as $line) {
            $colon = strpos($line, ':');
            if ($colon === false) {
                continue;
            }
            $name = strtolower(trim(substr($line, 0, $colon)));
            if ($name === 'transfer-encoding' && stripos(trim(substr($line, $colon + 1)), 'chunked') !== false) {
                $chunked = true;
            }
        }
        if ($chunked) {
            $body = self::dechunk($body);
        }
        return [$status, $body];
    }

    private static function dechunk(string $body): string
    {
        $out = '';
        $offset = 0;
        $length = strlen($body);
        while ($offset < $length) {
            $eol = strpos($body, "\r\n", $offset);
            if ($eol === false) {
                break;
            }
            $sizeHex = trim(substr($body, $offset, $eol - $offset));
            if ($sizeHex === '' || !ctype_xdigit($sizeHex)) {
                break;
            }
            $size = (int)hexdec($sizeHex);
            if ($size === 0 || $eol + 2 + $size > $length) {
                break;
            }
            $out .= substr($body, $eol + 2, $size);
            $offset = $eol + 2 + $size;
            if (substr($body, $offset, 2) === "\r\n") {
                $offset += 2;
            }
        }
        return $out;
    }

    private static function signedHeaderNames(array $headers): string
    {
        $names = array_keys(self::normalizedHeaders($headers));
        sort($names);
        return implode(';', $names);
    }

    private static function normalizedHeaders(array $headers): array
    {
        $out = [];
        foreach ($headers as $name => $value) {
            $out[strtolower(trim((string)$name))] = trim((string)$value);
        }
        return $out;
    }

    /** Percent-encode a key path segment-wise so '/' separators survive. */
    private static function encodePath(string $path): string
    {
        $parts = [];
        foreach (explode('/', $path) as $segment) {
            $parts[] = rawurlencode($segment);
        }
        return implode('/', $parts);
    }
}
