<?php
namespace Wawoo\Plugin\S3;

/**
 * Rewrites content media URLs to the object-storage public base in memory.
 *
 * Registered on the post.load and page.load hooks, which fire with the post
 * or page array by reference before any template renders, so no stored file
 * ever changes. Covers both the cover image and every site-rooted media
 * src/href in the rendered html.
 */
final class MediaRewrite
{
    public function handle(array &$payload = null): void
    {
        if ($payload === null || !is_array($payload)) {
            return;
        }
        if (!Config::enabled()) {
            return;
        }
        $base = Config::baseUrl();
        if ($base === '') {
            return;
        }
        if (isset($payload['cover']) && is_string($payload['cover']) && $payload['cover'] !== '') {
            $rewritten = self::rewritePath($payload['cover'], $base);
            if ($rewritten !== $payload['cover']) {
                $payload['cover'] = $rewritten;
            }
        }
        if (isset($payload['html']) && is_string($payload['html']) && $payload['html'] !== '') {
            $payload['html'] = self::rewriteHtml($payload['html'], $base);
        }
    }

    /**
     * Prefix a site-rooted media path with the public base. External URLs
     * (http:, https:, //host, data:, mailto:, …) are left untouched.
     */
    public static function rewritePath(string $url, string $base): string
    {
        if ($url === '' || $base === '') {
            return $url;
        }
        if (preg_match('#^(?:[a-z][a-z0-9+.-]*:|//|data:)#i', $url)) {
            return $url;
        }
        $path = self::stripBasePath($url);
        foreach (['/posts/', '/pages/', '/uploads/'] as $prefix) {
            if (strpos($path, $prefix) === 0) {
                return $base . $path;
            }
        }
        return $url;
    }

    /**
     * String-level src/href rewriting: every quoted media URL rooted at
     * /uploads/, /posts/ or /pages/ (optionally under BASE_PATH) gains the
     * public base. Attribute-agnostic on purpose (src=, href=, srcset-free).
     */
    public static function rewriteHtml(string $html, string $base): string
    {
        if ($html === '' || $base === '') {
            return $html;
        }
        $pairs = [];
        foreach (self::pathRoots() as $root) {
            foreach (['uploads', 'posts', 'pages'] as $segment) {
                $prefix = $root . '/' . $segment . '/';
                foreach (['"', "'"] as $quote) {
                    $pairs[$quote . $prefix] = $quote . $base . '/' . $segment . '/';
                }
            }
        }
        return $pairs === [] ? $html : strtr($html, $pairs);
    }

    /**
     * '/' or '' installations are site-rooted. Sub-path installs prefix
     * media URLs with BASE_PATH; both shapes are rewritten, the BASE_PATH
     * prefix itself is dropped from the object URL.
     */
    private static function pathRoots(): array
    {
        $root = self::basePathRoot();
        return $root === '' ? [''] : ['', $root];
    }

    private static function stripBasePath(string $path): string
    {
        $root = self::basePathRoot();
        if ($root !== '' && strpos($path, $root . '/') === 0) {
            return substr($path, strlen($root));
        }
        return $path;
    }

    private static function basePathRoot(): string
    {
        if (!defined('BASE_PATH')) {
            return '';
        }
        $base = rtrim((string)BASE_PATH, '/');
        return $base === '' || $base === '/' ? '' : $base;
    }
}
