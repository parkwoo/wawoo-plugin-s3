<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Wawoo\Plugin\S3\Client;
use Wawoo\Plugin\S3\Config;
use Wawoo\Plugin\S3\Settings;

/**
 * SSRF hardening tests for the S3 plugin. Endpoint validation must never
 * permit loopback/private/link-local/unspecified hosts, plain http is only
 * possible behind the explicit allow_http flag, and the Client must refuse
 * blocked endpoints before any request is made. All tests run in-process;
 * nothing ever reaches the network.
 */
final class S3SsrfTest extends TestCase
{
    protected function setUp(): void
    {
        $_POST = [];
        $_SERVER['REQUEST_METHOD'] = 'GET';
        unset($GLOBALS['WAWOO_S3']);
        Client::$resolver = function (string $host): array {
            $public = [
                's3.amazonaws.com',
                'cdn.example.com',
                'example.com',
                's3.example.com',
                'example-bucket.s3.us-east-1.amazonaws.com',
                's3.us-east-2.amazonaws.com',
            ];
            return in_array($host, $public, true) ? ['8.8.8.8'] : [];
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

    public function testRejectsPlainHttpByDefault(): void
    {
        $this->assertNull(Client::validateEndpoint('http://example.com'));
        $this->assertNull(Client::validateEndpoint('http://s3.example.com:9000'));
    }

    public function testRejectsLoopbackAndUnspecifiedAddresses(): void
    {
        $this->assertNull(Client::validateEndpoint('https://127.0.0.1'));
        $this->assertNull(Client::validateEndpoint('https://127.0.1.2:443'));
        $this->assertNull(Client::validateEndpoint('https://[::1]'));
        $this->assertNull(Client::validateEndpoint('https://[::]'));
        $this->assertNull(Client::validateEndpoint('https://0.0.0.0'));
    }

    public function testRejectsLinkLocalMetadataAddress(): void
    {
        $this->assertNull(Client::validateEndpoint('https://169.254.169.254'));
    }

    public function testRejectsRfc1918PrivateAddresses(): void
    {
        $this->assertNull(Client::validateEndpoint('https://10.1.2.3'));
        $this->assertNull(Client::validateEndpoint('https://192.168.0.1'));
        $this->assertNull(Client::validateEndpoint('https://172.16.5.5'));
    }

    public function testRejectsUniqueLocalIpv6Addresses(): void
    {
        $this->assertNull(Client::validateEndpoint('https://[fc00::1]'));
        $this->assertNull(Client::validateEndpoint('https://[fd12:3456::1]'));
    }

    public function testRejectsHostnameResolvingToPrivate(): void
    {
        $this->assertNull(Client::validateEndpoint('https://localhost'));
    }

    public function testRejectsEmptyEndpoint(): void
    {
        $this->assertNull(Client::validateEndpoint(''));
        $this->assertNull(Client::validateEndpoint('   '));
    }

    public function testRejectsMalformedEndpointsBeforeDnsLookup(): void
    {
        $this->assertNull(Client::validateEndpoint('not a url'));
        $this->assertNull(Client::validateEndpoint('ftp://s3.example.com'));
        $this->assertNull(Client::validateEndpoint('https://s3.example.com/bucket'));
        $this->assertNull(Client::validateEndpoint('https://user:pass@s3.example.com'));
        $this->assertNull(Client::validateEndpoint('https://s3.example.com:8080'));
        $this->assertNull(Client::validateEndpoint('https://s3.example.com?x=1'));
    }

    public function testAcceptsPublicHttpsEndpoints(): void
    {
        $this->assertSame('https://s3.amazonaws.com', Client::validateEndpoint('https://s3.amazonaws.com'));
        $this->assertSame('https://s3.amazonaws.com', Client::validateEndpoint('https://s3.amazonaws.com/'));
        $this->assertSame(
            'https://example-bucket.s3.us-east-1.amazonaws.com',
            Client::validateEndpoint('https://example-bucket.s3.us-east-1.amazonaws.com')
        );
        $this->assertSame('https://cdn.example.com:8443', Client::validateEndpoint('https://cdn.example.com:8443'));
    }

    public function testAllowHttpLiftsSchemeButNeverHostRestrictions(): void
    {
        $allow = ['allow_http' => true];
        $this->assertSame('http://example.com', Client::validateEndpoint('http://example.com', $allow));
        $this->assertSame('http://example.com:9000', Client::validateEndpoint('http://example.com:9000', $allow));
        $this->assertNull(Client::validateEndpoint('http://127.0.0.1:9000', $allow));
        $this->assertNull(Client::validateEndpoint('http://localhost', $allow));
        $this->assertNull(Client::validateEndpoint('http://10.0.0.5', $allow));
        $this->assertNull(Client::validateEndpoint('https://169.254.169.254', $allow));
    }

    public function testClientRefusesBlockedOrInsecureEndpointsBeforeRequesting(): void
    {
        foreach (['https://169.254.169.254', 'http://127.0.0.1:9000', 'http://example.com'] as $endpoint) {
            $client = new Client([
                'endpoint'   => $endpoint,
                'bucket'     => 'b',
                'access_key' => 'a',
                'secret_key' => 's',
            ]);
            $this->assertFalse($client->objectExists('x'));
            $this->assertFalse($client->putObject('x', 'data', 'text/plain'));
            $this->assertFalse($client->putBucket());
        }
    }

    public function testSaveFromPostRejectsPrivateEndpointAndWritesNothing(): void
    {
        $error = null;
        $result = Settings::saveFromPost([
            'endpoint'   => 'https://169.254.169.254',
            'bucket'     => 'b',
            'access_key' => 'a',
            'secret_key' => 's',
        ], $error);

        $this->assertSame('Endpoint must be a public https:// URL (no private/loopback hosts).', $error);
        $this->assertSame('https://s3.amazonaws.com', $result['endpoint']);
        $this->assertFileDoesNotExist(rtrim(CACHE_DIR, '/\\') . '/settings/s3.json');
    }

    public function testSaveFromPostRejectsHttpUnlessAllowHttpChecked(): void
    {
        $error = null;
        $result = Settings::saveFromPost([
            'endpoint'   => 'http://example.com',
            'bucket'     => 'b',
            'access_key' => 'a',
            'secret_key' => 's',
        ], $error);

        $this->assertNotNull($error);
        $this->assertSame('https://s3.amazonaws.com', $result['endpoint']);
        $this->assertFileDoesNotExist(rtrim(CACHE_DIR, '/\\') . '/settings/s3.json');
    }

    public function testSaveFromPostPersistsPublicHttpWithAllowHttp(): void
    {
        $error = null;
        $result = Settings::saveFromPost([
            'endpoint'    => 'http://example.com',
            'allow_http'  => '1',
            'bucket'      => 'b',
            'access_key'  => 'a',
            'secret_key'  => 's',
            'path_style'  => '1',
            'force_path'  => '',
        ], $error);

        $this->assertNull($error);
        $this->assertTrue($result['allow_http']);
        $this->assertSame('http://example.com', $result['endpoint']);

        $this->resetConfigCache();
        $cfg = Config::all();
        $this->assertTrue($cfg['allow_http']);
        $this->assertSame('http://example.com', $cfg['endpoint']);
    }

    public function testSaveFromPostPersistsPublicHttpsEndpoint(): void
    {
        $error = null;
        $result = Settings::saveFromPost([
            'endpoint'   => 'https://s3.us-east-2.amazonaws.com',
            'allow_http' => '',
            'bucket'     => 'b',
            'access_key' => 'a',
            'secret_key' => 's',
        ], $error);

        $this->assertNull($error);
        $this->assertFalse($result['allow_http']);
        $this->assertSame('https://s3.us-east-2.amazonaws.com', $result['endpoint']);
    }

    private function writeSettings(array $data): void
    {
        $file = rtrim(CACHE_DIR, '/\\') . '/settings/s3.json';
        $dir = dirname($file);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        file_put_contents($file, json_encode($data));
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
