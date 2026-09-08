<?php
namespace Wawoo\Plugin\S3;

/**
 * Discovers content media (images and other binary assets living next to
 * markdown and under uploads/) and mirrors it to S3-compatible storage.
 *
 * Local files stay the source of truth; only the object copies live in the
 * bucket. Relative web paths ('posts/<slug>/x.png', 'pages/<slug>/x.svg',
 * 'uploads/x.png') are used as the canonical key shape.
 */
final class Media
{
    /**
     * All media files as site-relative web paths, e.g.
     * 'posts/hello/hero.png'. Accepts explicit base directories for tests;
     * without arguments the configured POSTS_DIR, PAGES_DIR and uploads
     * directory are walked.
     */
    public static function discover(?array $dirs = null): array
    {
        $found = [];
        foreach (self::bases($dirs) as $label => $dir) {
            if (!is_dir($dir)) {
                continue;
            }
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
            );
            foreach ($iterator as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                $rel = self::relativeUnder($label, $dir, $file->getPathname());
                if (self::isMedia($rel)) {
                    $found[] = $rel;
                }
            }
        }
        sort($found);
        return array_values(array_unique($found));
    }

    /**
     * Map an absolute file path onto its site-relative web path. A file in
     * posts/<slug>/ resolves to 'posts/<slug>/…', pages and uploads alike.
     */
    public static function relativeOf(string $absPath): string
    {
        $path = str_replace('\\', '/', $absPath);
        foreach (self::bases(null) as $label => $dir) {
            $prefix = str_replace('\\', '/', $dir);
            if ($path === $prefix) {
                return $label;
            }
            if ($prefix !== '/' && strpos($path, $prefix . '/') === 0) {
                return $label . '/' . substr($path, strlen($prefix) + 1);
            }
        }
        if (defined('POSTS_DIR')) {
            $root = dirname(rtrim((string)POSTS_DIR, '/\\'));
            if (strpos($path, $root . '/') === 0) {
                return substr($path, strlen($root) + 1);
            }
        }
        return ltrim($path, '/');
    }

    /**
     * Resolve a site-relative web path back to an absolute file path, or ''
     * when no configured base directory owns it.
     */
    public static function absoluteOf(string $rel): string
    {
        $rel = ltrim(str_replace('\\', '/', $rel), '/');
        foreach (self::bases(null) as $label => $dir) {
            $prefix = $label . '/';
            if ($rel === $label) {
                return $dir;
            }
            if (strpos($rel, $prefix) === 0) {
                return $dir . '/' . substr($rel, strlen($prefix));
            }
        }
        return '';
    }

    public static function publicUrl(string $relPath): string
    {
        if (!Config::enabled()) {
            return '';
        }
        $base = Config::baseUrl();
        if ($base === '') {
            return '';
        }
        $rel = ltrim(str_replace('\\', '/', $relPath), '/');
        return $rel === '' ? $base : $base . '/' . $rel;
    }

    /**
     * Upload every discovered media file to the bucket. When force_path is
     * false an object that already exists is left untouched (bandwidth
     * saving); with force_path true every file is re-uploaded.
     *
     * Returns ['uploaded' => n, 'failed' => [rel, ...], 'keys' => [rel => key]].
     */
    public static function sync(?callable $progress = null): array
    {
        $cfg = Config::all();
        $client = new Client($cfg);
        $force = !empty($cfg['force_path']);

        $uploaded = 0;
        $failed = [];
        $keys = [];
        foreach (self::discover() as $rel) {
            $file = self::absoluteOf($rel);
            if ($file === '' || !is_file($file)) {
                $failed[] = $rel;
                if ($progress !== null) {
                    $progress($rel, false);
                }
                continue;
            }
            $key = Config::objectKeyForRelativePath($rel);
            $keys[$rel] = $key;
            $ok = !$force && $client->objectExists($key);
            if (!$ok) {
                $ok = $client->putObject($key, (string)@file_get_contents($file), Client::contentTypeFor($rel));
            }
            if ($ok) {
                $uploaded++;
            } else {
                $failed[] = $rel;
            }
            if ($progress !== null) {
                $progress($rel, $ok);
            }
        }
        return ['uploaded' => $uploaded, 'failed' => $failed, 'keys' => $keys];
    }

    private static function bases(?array $dirs): array
    {
        if ($dirs !== null) {
            $out = [];
            foreach ($dirs as $dir) {
                $d = rtrim(str_replace('\\', '/', (string)$dir), '/');
                if ($d !== '') {
                    $out[basename($d)] = $d;
                }
            }
            return $out;
        }
        $out = [];
        if (defined('POSTS_DIR')) {
            $out['posts'] = rtrim(str_replace('\\', '/', (string)POSTS_DIR), '/');
        }
        if (defined('PAGES_DIR')) {
            $out['pages'] = rtrim(str_replace('\\', '/', (string)PAGES_DIR), '/');
        }
        $uploads = defined('UPLOADS_DIR') && (string)UPLOADS_DIR !== ''
            ? (string)UPLOADS_DIR
            : (defined('POSTS_DIR') ? dirname(rtrim((string)POSTS_DIR, '/\\')) . '/uploads' : '');
        if ($uploads !== '') {
            $out['uploads'] = rtrim(str_replace('\\', '/', $uploads), '/');
        }
        return $out;
    }

    private static function relativeUnder(string $label, string $dir, string $path): string
    {
        $path = str_replace('\\', '/', $path);
        $dir = rtrim(str_replace('\\', '/', $dir), '/');
        $rel = substr($path, strlen($dir));
        $rel = trim($rel, '/');
        return $rel === '' ? $label : $label . '/' . $rel;
    }

    private static function isMedia(string $rel): bool
    {
        foreach (explode('/', $rel) as $segment) {
            if ($segment === '' || $segment === 'cache' || $segment[0] === '.') {
                return false;
            }
        }
        $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
        return $ext !== 'md' && $ext !== 'markdown';
    }
}
