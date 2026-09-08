<?php
namespace Wawoo\Plugin\S3;

/**
 * Merges plugin.json defaults with the optional $WAWOO_S3 override
 * defined in config.local.php, then applies any settings saved by the
 * admin UI (CACHE_DIR/settings/s3.json) on top.
 *
 * Priority: settings file > $WAWOO_S3 > manifest defaults.
 */
final class Config
{
    private static $cache = null;

    public static function all(): array
    {
        if (self::$cache !== null) {
            return self::$cache;
        }
        $defaults = [];
        $file = dirname(__DIR__) . '/plugin.json';
        if (is_file($file)) {
            $raw = json_decode((string)file_get_contents($file), true);
            if (is_array($raw) && isset($raw['config']) && is_array($raw['config'])) {
                $defaults = $raw['config'];
            }
        }
        $override = [];
        if (isset($GLOBALS['WAWOO_S3']) && is_array($GLOBALS['WAWOO_S3'])) {
            $override = $GLOBALS['WAWOO_S3'];
        }
        return self::$cache = array_replace($defaults, $override, self::settings());
    }

    public static function enabled(): bool
    {
        return !empty(self::all()['enabled']);
    }

    public static function baseUrl(): string
    {
        $base = trim((string)(self::all()['public_base'] ?? ''));
        return $base === '' ? '' : rtrim($base, '/');
    }

    public static function objectKeyForRelativePath(string $rel): string
    {
        $rel = ltrim(str_replace('\\', '/', $rel), '/');
        $prefix = trim((string)(self::all()['prefix'] ?? ''), '/');
        if ($rel === '') {
            return $prefix;
        }
        return $prefix === '' ? $rel : $prefix . '/' . $rel;
    }

    private static function settings(): array
    {
        $file = rtrim(\CACHE_DIR, '/\\') . DIRECTORY_SEPARATOR . 'settings'
            . DIRECTORY_SEPARATOR . 's3.json';
        if (!is_file($file)) {
            return [];
        }
        $raw = json_decode((string)@file_get_contents($file), true);
        return is_array($raw) ? $raw : [];
    }
}
