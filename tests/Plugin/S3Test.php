<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Wawoo\Plugin\S3\Client;
use Wawoo\Plugin\S3\Config;
use Wawoo\Plugin\S3\Media;
use Wawoo\Plugin\S3\MediaRewrite;
use Wawoo\Plugin\S3\Settings;

/**
 * S3 media-sync plugin tests. Config, signing helpers, discovery and URL
 * rewriting are exercised in-process; nothing ever reaches the network.
 */
final class S3Test extends TestCase
{
    private const FIXTURE_SECRET = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';

    protected function setUp(): void
    {
        $_POST = [];
        $_SERVER['REQUEST_METHOD'] = 'GET';
        unset($GLOBALS['WAWOO_S3']);
        Client::$resolver = function (string $host): array {
            return in_array($host, [
                'minio.example.internal',
                's3.amazonaws.com',
                'cdn.example.com',
                'example.com',
                's3.us-east-2.amazonaws.com',
            ], true) ? ['8.8.8.8'] : [];
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

    public function testConfigDefaultsComeFromPluginJson(): void
    {
        $cfg = Config::all();
        $this->assertFalse($cfg['enabled']);
        $this->assertSame('https://s3.amazonaws.com', $cfg['endpoint']);
        $this->assertSame('us-east-1', $cfg['region']);
        $this->assertSame('', $cfg['bucket']);
        $this->assertSame('', $cfg['public_base']);
        $this->assertSame('media', $cfg['prefix']);
        $this->assertTrue($cfg['path_style']);
        $this->assertFalse($cfg['force_path']);
    }

    public function testConfigGlobalsOverridePluginJson(): void
    {
        $GLOBALS['WAWOO_S3'] = [
            'endpoint' => 'https://s3.eu-central-1.amazonaws.com',
            'bucket'   => 'cdn-bucket',
            'enabled'  => true,
        ];
        $this->resetConfigCache();

        $cfg = Config::all();
        $this->assertSame('https://s3.eu-central-1.amazonaws.com', $cfg['endpoint']);
        $this->assertSame('cdn-bucket', $cfg['bucket']);
        $this->assertTrue($cfg['enabled']);
        $this->assertSame('media', $cfg['prefix']);
        $this->assertSame('us-east-1', $cfg['region']);
    }

    public function testConfigSettingsFileOverridesGlobals(): void
    {
        $this->writeSettings(['region' => 'eu-west-1', 'prefix' => 'assets', 'enabled' => true]);
        $GLOBALS['WAWOO_S3'] = ['endpoint' => 'http://globals.example', 'region' => 'ap-south-1'];
        $this->resetConfigCache();

        $cfg = Config::all();
        $this->assertSame('http://globals.example', $cfg['endpoint']);
        $this->assertSame('eu-west-1', $cfg['region']);
        $this->assertSame('assets', $cfg['prefix']);
        $this->assertTrue($cfg['enabled']);
    }

    public function testObjectKeyPrefixing(): void
    {
        $this->assertSame('media/posts/hello/hero.png', Config::objectKeyForRelativePath('posts/hello/hero.png'));
        $this->assertSame('media/uploads/logo.png', Config::objectKeyForRelativePath('/uploads/logo.png'));

        $GLOBALS['WAWOO_S3'] = ['prefix' => ''];
        $this->resetConfigCache();
        $this->assertSame('posts/hello/hero.png', Config::objectKeyForRelativePath('posts/hello/hero.png'));

        $GLOBALS['WAWOO_S3'] = ['prefix' => 'assets/'];
        $this->resetConfigCache();
        $this->assertSame('assets/posts/hello/hero.png', Config::objectKeyForRelativePath('posts/hello/hero.png'));
    }

    public function testSigningKeyMatchesReferenceVector(): void
    {
        // AWS SigV4 signing key for the documented get-user credentials.
        // Independent reference values (PHP hash_hmac and Python hmac agree).
        $this->assertSame(
            '0138c7a6cbd60aa727b2f653a522567439dfb9f3e72b21f9b25941a42f04a7cd',
            bin2hex(Client::hmacSha256('AWS4' . self::FIXTURE_SECRET, '20150830'))
        );
        $this->assertSame(
            'c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9',
            bin2hex(Client::signingKey(self::FIXTURE_SECRET, '20150830', 'us-east-1', 'iam'))
        );
    }

    public function testSigningKeyMatchesPublishedExampleChain(): void
    {
        // The AWS General Reference get-user example chain for 20120215.
        $this->assertSame(
            'f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d',
            bin2hex(Client::signingKey(self::FIXTURE_SECRET, '20120215', 'us-east-1', 'iam'))
        );
    }

    public function testCanonicalRequestIsDeterministic(): void
    {
        $payloadHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        $canonical = Client::canonicalRequest(
            'PUT',
            '/demo-bucket/media/posts/hello/hero.png',
            '',
            [
                'host'                 => 's3.example.com',
                'x-amz-content-sha256' => $payloadHash,
                'x-amz-date'           => '20260908T120000Z',
            ],
            $payloadHash
        );

        $expected = "PUT\n"
            . "/demo-bucket/media/posts/hello/hero.png\n"
            . "\n"
            . "host:s3.example.com\n"
            . "x-amz-content-sha256:" . $payloadHash . "\n"
            . "x-amz-date:20260908T120000Z\n"
            . "\n"
            . "host;x-amz-content-sha256;x-amz-date\n"
            . $payloadHash;

        $this->assertSame($expected, $canonical);
        $this->assertStringContainsString('s3.example.com', $canonical);
        $this->assertStringContainsString('demo-bucket/media/posts/hello/hero.png', $canonical);
        $this->assertStringContainsString('host;x-amz-content-sha256;x-amz-date', $canonical);
    }

    public function testContentTypeMap(): void
    {
        $this->assertSame('image/png', Client::contentTypeFor('x.png'));
        $this->assertSame('image/svg+xml', Client::contentTypeFor('a.SVG'));
        $this->assertSame('application/pdf', Client::contentTypeFor('doc.pdf'));
        $this->assertSame('application/javascript', Client::contentTypeFor('app.js'));
        $this->assertSame('application/octet-stream', Client::contentTypeFor('file.bin'));
    }

    public function testRelativeOfMapsKnownBaseDirs(): void
    {
        $this->assertSame(
            'posts/welcome/hero.png',
            Media::relativeOf(rtrim(POSTS_DIR, '/\\') . '/welcome/hero.png')
        );
        $this->assertSame(
            'pages/about/team.svg',
            Media::relativeOf(rtrim(PAGES_DIR, '/\\') . '/about/team.svg')
        );
    }

    public function testDiscoverWalksContentDirsAndSkipsNonMedia(): void
    {
        $site = rtrim(CACHE_DIR, '/\\') . '/s3site';
        $files = [
            'posts/welcome/hero.png',
            'posts/welcome/hero.md',
            'posts/welcome/readme.txt',
            'posts/welcome/.hidden.png',
            'posts/welcome/.dir/inner.png',
            'posts/welcome/gallery/img.jpg',
            'pages/about/team.svg',
            'pages/about/index.md',
            'uploads/logo.png',
            'uploads/cache/thumb.png',
        ];
        foreach ($files as $rel) {
            $this->makeFile($site . '/' . $rel, 'data');
        }

        $found = Media::discover([
            $site . '/posts',
            $site . '/pages',
            $site . '/uploads',
        ]);

        $this->assertSame([
            'pages/about/team.svg',
            'posts/welcome/gallery/img.jpg',
            'posts/welcome/hero.png',
            'posts/welcome/readme.txt',
            'uploads/logo.png',
        ], $found);
        $this->assertNotContains('posts/welcome/hero.md', $found);
        $this->assertNotContains('posts/welcome/.hidden.png', $found);
        $this->assertNotContains('posts/welcome/.dir/inner.png', $found);
        $this->assertNotContains('uploads/cache/thumb.png', $found);
    }

    public function testPublicUrlRespectsEnabledAndBase(): void
    {
        $GLOBALS['WAWOO_S3'] = [
            'enabled'     => true,
            'public_base' => 'https://cdn.example.com/media',
            'bucket'      => 'b',
        ];
        $this->resetConfigCache();
        $this->assertSame(
            'https://cdn.example.com/media/uploads/logo.png',
            Media::publicUrl('uploads/logo.png')
        );
        $this->assertSame(
            'https://cdn.example.com/media/posts/welcome/hero.png',
            Media::publicUrl('/posts/welcome/hero.png')
        );

        $GLOBALS['WAWOO_S3'] = ['enabled' => false, 'public_base' => 'https://cdn.example.com/media'];
        $this->resetConfigCache();
        $this->assertSame('', Media::publicUrl('uploads/logo.png'));
    }

    public function testMediaRewriteRewritesCoverAndHtmlWhenEnabled(): void
    {
        $GLOBALS['WAWOO_S3'] = [
            'enabled'     => true,
            'public_base' => 'https://cdn.example.com/media',
        ];
        $this->resetConfigCache();

        $post = [
            'slug'  => 'demo',
            'cover' => '/posts/demo/cover.jpg',
            'html'  => '<p><img src="/uploads/a.png" alt="a"></p>'
                . '<p><a href="/posts/demo/spec.pdf">pdf</a></p>'
                . '<img src="https://external.example.com/b.png">'
                . '<img src="//cdn.other.example.com/c.png">',
        ];
        (new MediaRewrite())->handle($post);

        $this->assertSame('https://cdn.example.com/media/posts/demo/cover.jpg', $post['cover']);
        $this->assertStringContainsString('src="https://cdn.example.com/media/uploads/a.png"', $post['html']);
        $this->assertStringContainsString('href="https://cdn.example.com/media/posts/demo/spec.pdf"', $post['html']);
        $this->assertStringContainsString('src="https://external.example.com/b.png"', $post['html']);
        $this->assertStringContainsString('src="//cdn.other.example.com/c.png"', $post['html']);
    }

    public function testMediaRewriteLeavesEverythingWhenDisabled(): void
    {
        $GLOBALS['WAWOO_S3'] = ['enabled' => false, 'public_base' => 'https://cdn.example.com/media'];
        $this->resetConfigCache();

        $post = [
            'slug'  => 'demo',
            'cover' => '/posts/demo/cover.jpg',
            'html'  => '<img src="/uploads/a.png">',
        ];
        (new MediaRewrite())->handle($post);

        $this->assertSame('/posts/demo/cover.jpg', $post['cover']);
        $this->assertSame('<img src="/uploads/a.png">', $post['html']);
    }

    public function testMediaRewriteSkipsExternalCoverUrls(): void
    {
        $GLOBALS['WAWOO_S3'] = ['enabled' => true, 'public_base' => 'https://cdn.example.com/media'];
        $this->resetConfigCache();

        $post = [
            'cover' => 'https://remote.example.com/hero.png',
            'html'  => '<img src="/pages/about/x.svg">',
        ];
        (new MediaRewrite())->handle($post);

        $this->assertSame('https://remote.example.com/hero.png', $post['cover']);
        $this->assertStringContainsString('src="https://cdn.example.com/media/pages/about/x.svg"', $post['html']);
    }

    public function testSaveFromPostPersistsConfigAndKeepsBlankCredentials(): void
    {
        $GLOBALS['WAWOO_S3'] = [
            'enabled'    => true,
            'access_key' => 'AKIAOLDKEY',
            'secret_key' => 'old-secret-value',
        ];
        $this->resetConfigCache();

        $result = Settings::saveFromPost([
            'enabled'     => '1',
            'endpoint'    => 'https://minio.example.internal',
            'region'      => 'eu-central-1',
            'bucket'      => 'media-bucket',
            'access_key'  => '',
            'secret_key'  => '',
            'public_base' => 'https://cdn.example.com/media',
            'prefix'      => 'assets',
            'path_style'  => '1',
            'force_path'  => '',
        ]);

        $this->assertTrue($result['enabled']);
        $this->assertSame('https://minio.example.internal', $result['endpoint']);
        $this->assertSame('eu-central-1', $result['region']);
        $this->assertSame('media-bucket', $result['bucket']);
        $this->assertSame('https://cdn.example.com/media', $result['public_base']);
        $this->assertSame('assets', $result['prefix']);
        $this->assertSame('AKIAOLDKEY', $result['access_key']);
        $this->assertSame('old-secret-value', $result['secret_key']);
        $this->assertTrue($result['path_style']);
        $this->assertFalse($result['force_path']);

        $file = rtrim(CACHE_DIR, '/\\') . '/settings/s3.json';
        $this->assertFileExists($file);
        $saved = json_decode((string)file_get_contents($file), true);
        $this->assertSame('media-bucket', $saved['bucket']);
        $this->assertSame('old-secret-value', $saved['secret_key']);

        $this->resetConfigCache();
        $cfg = Config::all();
        $this->assertSame('https://minio.example.internal', $cfg['endpoint']);
        $this->assertSame('AKIAOLDKEY', $cfg['access_key']);
        $this->assertSame('assets', $cfg['prefix']);
    }

    public function testSaveFromPostReplacesCredentialsWhenProvided(): void
    {
        $result = Settings::saveFromPost([
            'enabled'     => '',
            'endpoint'    => '',
            'bucket'      => 'new-bucket',
            'access_key'  => 'AKIANEWKEY',
            'secret_key'  => 'new-secret-value',
            'prefix'      => 'media',
        ]);

        $this->assertFalse($result['enabled']);
        $this->assertSame('AKIANEWKEY', $result['access_key']);
        $this->assertSame('new-secret-value', $result['secret_key']);
        $this->assertSame('new-bucket', $result['bucket']);
        $this->assertSame('https://s3.amazonaws.com', $result['endpoint']);
    }

    private function makeFile(string $rel, string $contents): void
    {
        $path = str_replace('\\', '/', $rel);
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        file_put_contents($path, $contents);
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
        $site = rtrim(CACHE_DIR, '/\\') . '/s3site';
        if (is_dir($site)) {
            $this->rmDir($site);
        }
    }

    private function rmDir(string $dir): void
    {
        foreach (scandir($dir) as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $p = $dir . '/' . $entry;
            if (is_dir($p) && !is_link($p)) {
                $this->rmDir($p);
            } else {
                @unlink($p);
            }
        }
        @rmdir($dir);
    }
}
