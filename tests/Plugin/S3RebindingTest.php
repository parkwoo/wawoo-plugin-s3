<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Wawoo\Plugin\S3\Client;
use Wawoo\Plugin\S3\Config;

/**
 * DNS-rebinding hardening tests for the S3 Client transport. The constructor
 * validates the endpoint once and pins the verified public addresses; request
 * methods must never trigger a second DNS resolution or connect anywhere when
 * no public address could be pinned. All tests run in-process; nothing ever
 * reaches the network (only DNS lookups happen during pinning assertions).
 */
final class S3RebindingTest extends TestCase
{
    protected function setUp(): void
    {
        $_POST = [];
        $_SERVER['REQUEST_METHOD'] = 'GET';
        unset($GLOBALS['WAWOO_S3']);
        // Deterministic, network-independent DNS: public host resolves to a
        // public IP; unresolvable names return nothing. Never touch real DNS.
        Client::$resolver = function (string $host): array {
            switch ($host) {
                case 's3.amazonaws.com':
                case 'cdn.example.com':
                    return ['8.8.8.8'];
                case 'example.com':
                    return ['1.1.1.1'];
                default:
                    return [];
            }
        };
        $this->resetConfigCache();
        $this->cleanupFiles();
    }

    protected function tearDown(): void
    {
        $_POST = [];
        $_SERVER['REQUEST_METHOD'] = 'GET';
        unset($GLOBALS['WAWOO_S3']);
        Client::$resolver = null;
        $this->resetConfigCache();
        $this->cleanupFiles();
    }

    public function testConstructorPinsPublicHostnameAddresses(): void
    {
        $client = new Client(self::cfg('https://s3.amazonaws.com'));

        $this->assertSame('s3.amazonaws.com', $client->pinnedHost());
        $ip = $client->pinnedIp();
        $this->assertNotNull($ip);
        $this->assertNotSame('', $ip);
        $this->assertNotFalse(filter_var($ip, FILTER_VALIDATE_IP));
        $this->assertNotSame('127.0.0.1', $ip);

        $pinned = Client::resolvePinnedAddresses('s3.amazonaws.com');
        $this->assertNotNull($pinned);
        foreach ($pinned as $address) {
            $this->assertNotFalse(filter_var($address, FILTER_VALIDATE_IP));
        }
    }

    public function testLiteralPublicIpEndpointPinsItself(): void
    {
        $client = new Client(self::cfg('https://8.8.8.8'));

        $this->assertSame('8.8.8.8', $client->pinnedHost());
        $this->assertSame('8.8.8.8', $client->pinnedIp());
    }

    public function testBlockedLiteralEndpointsFailClosedWithoutNetwork(): void
    {
        foreach (['https://127.0.0.1', 'https://10.0.0.5', 'https://[::1]', 'https://169.254.169.254'] as $endpoint) {
            $client = new Client(self::cfg($endpoint));
            $this->assertNull($client->pinnedHost(), $endpoint);
            $this->assertNull($client->pinnedIp(), $endpoint);
            $this->assertFalse($client->objectExists('x'));
            $this->assertFalse($client->putObject('x', 'data', 'text/plain'));
            $this->assertFalse($client->deleteObject('x'));
            $this->assertFalse($client->putBucket());
        }
    }

    public function testUnresolvableHostnameFailsClosedWithoutNetwork(): void
    {
        $client = new Client(self::cfg('https://example.invalid'));

        $this->assertNull($client->pinnedIp());
        $this->assertFalse($client->objectExists('x'));
        $this->assertFalse($client->putObject('x', 'data', 'text/plain'));
        $this->assertFalse($client->putBucket());
    }

    public function testMissingCredentialsFailsBeforeAnyConnection(): void
    {
        $client = new Client([
            'endpoint' => 'https://s3.amazonaws.com',
            'bucket'   => '',
            'access_key' => '',
            'secret_key' => '',
        ]);

        $this->assertNotNull($client->pinnedIp());
        $this->assertFalse($client->objectExists('x'));
        $this->assertFalse($client->putObject('x', 'data', 'text/plain'));
        $this->assertFalse($client->putBucket());
    }

    public function testHttpWithAllowHttpUnresolvableHostFailsClosed(): void
    {
        $cfg = self::cfg('http://s3.invalid');
        $cfg['allow_http'] = true;
        $client = new Client($cfg);

        $this->assertNull($client->pinnedIp());
        $this->assertFalse($client->objectExists('x'));
        $this->assertFalse($client->putObject('x', 'data', 'text/plain'));
    }

    public function testSplitEndpointReturnsSchemeHostPort(): void
    {
        $this->assertSame(['https', 's3.amazonaws.com', null], Client::splitEndpoint('https://s3.amazonaws.com'));
        $this->assertSame(['https', 'cdn.example.com', 8443], Client::splitEndpoint('https://cdn.example.com:8443'));
        $this->assertSame(['http', 'example.com', 9000], Client::splitEndpoint('http://example.com:9000'));
        $this->assertNull(Client::splitEndpoint('https://s3.amazonaws.com/bucket'));
        $this->assertNull(Client::splitEndpoint('ftp://example.com'));
        $this->assertNull(Client::splitEndpoint('http://example.com:99999'));
        $this->assertNull(Client::splitEndpoint('not a url'));
        $this->assertNull(Client::splitEndpoint(''));
    }

    public function testResolvePinnedAddressesFiltersBlockedAddresses(): void
    {
        $this->assertNull(Client::resolvePinnedAddresses('127.0.0.1'));
        $this->assertNull(Client::resolvePinnedAddresses('10.1.2.3'));
        $this->assertNull(Client::resolvePinnedAddresses('169.254.169.254'));
        $this->assertNull(Client::resolvePinnedAddresses('example.invalid'));

        $pinned = Client::resolvePinnedAddresses('s3.amazonaws.com');
        $this->assertNotNull($pinned);
        $this->assertNotEmpty($pinned);
    }

    private static function cfg(string $endpoint): array
    {
        return [
            'endpoint'   => $endpoint,
            'bucket'     => 'b',
            'access_key' => 'a',
            'secret_key' => 's',
        ];
    }

    private function resetConfigCache(): void
    {
        $r = new ReflectionClass(Config::class);
        if ($r->hasProperty('cache')) {
            $p = $r->getProperty('cache');
            $p->setAccessible(true);
            $p->setValue(null, null);
        }
    }

    private function cleanupFiles(): void
    {
        foreach (glob(rtrim(CACHE_DIR, '/\\') . '/settings/s3.json*') ?: [] as $f) {
            @unlink($f);
        }
    }
}
