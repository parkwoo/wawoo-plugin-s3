<?php
namespace Wawoo\Plugin\S3;

/**
 * Admin settings page for the S3 media plugin, dispatched by the admin
 * console at /admin/?action=settings&plugin=s3 (requires "settings": true
 * in plugin.json). Persists runtime settings to CACHE_DIR/settings/s3.json
 * which Config merges with highest priority, and offers a manual "Sync now"
 * action that uploads every discovered media file to the bucket.
 */
final class Settings
{
    public function handle(?string $root = null): void
    {
        $notice = '';
        $error = '';
        $cfg = Config::all();

        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
            if (!\Wawoo\Plugin\Admin\Csrf::verify(\Wawoo\Plugin\Admin\Csrf::posted())) {
                $error = 'Invalid or missing CSRF token.';
            } else {
                $action = (string)($_POST['action'] ?? 'save');
                $saveError = '';
                $cfg = self::saveFromPost($_POST, $saveError);
                if ($action === 'sync' && $saveError === '') {
                    $missing = self::missingRequired($cfg);
                    if ($missing === []) {
                        $sync = Media::sync();
                        $failed = count($sync['failed']);
                        $notice = sprintf(
                            'Sync complete: %d media file(s) uploaded or verified, %d failed.',
                            $sync['uploaded'],
                            $failed
                        );
                        if ($failed > 0) {
                            $error = 'Failed objects: ' . implode(', ', array_slice($sync['failed'], 0, 10));
                        }
                    } else {
                        $error = 'Cannot sync until configured: ' . implode(', ', $missing) . '.';
                    }
                } elseif ($saveError !== '') {
                    $error = $saveError;
                    $cfg['endpoint'] = trim((string)($_POST['endpoint'] ?? ''));
                    $cfg['allow_http'] = !empty($_POST['allow_http']);
                } else {
                    $notice = 'Settings saved.';
                }
            }
        }

        $localCount = count(Media::discover());
        echo self::html($cfg, $notice, $error, $localCount);
    }

    /**
     * Validate and persist the settings form. Returns the resulting merged
     * config array (Config::all() view) so it can be unit-tested without
     * echoing or exiting. Blank access/secret fields keep the previously
     * effective credentials. When the submitted endpoint fails SSRF
     * validation nothing is written, $error is set, and the previously
     * effective config is returned.
     */
    public static function saveFromPost(array $post, ?string &$error = null): array
    {
        $cfg = Config::all();
        $endpoint = self::field($post, 'endpoint', $cfg);
        $probe = $cfg;
        $probe['allow_http'] = !empty($post['allow_http']);
        if (Client::validateEndpoint($endpoint, $probe) === null) {
            $error = 'Endpoint must be a public https:// URL (no private/loopback hosts).';
            return $cfg;
        }

        $settings = self::read();
        $settings['enabled'] = !empty($post['enabled']);
        $settings['endpoint'] = $endpoint;
        $settings['region'] = self::field($post, 'region', $cfg);
        $settings['bucket'] = self::field($post, 'bucket', $cfg);
        $settings['public_base'] = self::field($post, 'public_base', $cfg);
        $settings['prefix'] = self::field($post, 'prefix', $cfg);
        $settings['access_key'] = self::credential($post, 'access_key', $cfg);
        $settings['secret_key'] = self::credential($post, 'secret_key', $cfg);
        $settings['path_style'] = !empty($post['path_style']);
        $settings['force_path'] = !empty($post['force_path']);
        $settings['allow_http'] = !empty($post['allow_http']);
        self::write($settings);
        self::resetConfigCache();
        return Config::all();
    }

    private static function field(array $post, string $key, array $cfg): string
    {
        $value = trim((string)($post[$key] ?? ''));
        return $value !== '' ? $value : (string)($cfg[$key] ?? '');
    }

    private static function credential(array $post, string $key, array $cfg): string
    {
        $value = (string)($post[$key] ?? '');
        return $value !== '' ? $value : (string)($cfg[$key] ?? '');
    }

    private static function missingRequired(array $cfg): array
    {
        $missing = [];
        foreach (['endpoint', 'bucket', 'access_key', 'secret_key'] as $key) {
            if (trim((string)($cfg[$key] ?? '')) === '') {
                $missing[] = $key;
            }
        }
        return $missing;
    }

    private static function file(): string
    {
        return rtrim(\CACHE_DIR, '/\\') . DIRECTORY_SEPARATOR . 'settings'
            . DIRECTORY_SEPARATOR . 's3.json';
    }

    private static function read(): array
    {
        $f = self::file();
        if (!is_file($f)) {
            return [];
        }
        $data = json_decode((string)@file_get_contents($f), true);
        return is_array($data) ? $data : [];
    }

    private static function write(array $settings): void
    {
        $dir = dirname(self::file());
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        $f    = self::file();
        $lock = $f . '.lock';
        $tmp  = $f . '.' . bin2hex(random_bytes(4)) . '.tmp';
        $fh   = @fopen($lock, 'c');
        if ($fh === false) {
            @file_put_contents($f, json_encode($settings));
            return;
        }
        flock($fh, LOCK_EX);
        $ok = @file_put_contents($tmp, json_encode($settings)) !== false;
        if ($ok) {
            $ok = @rename($tmp, $f);
        }
        if (!$ok) {
            @unlink($tmp);
        }
        flock($fh, LOCK_UN);
        fclose($fh);
        @unlink($lock);
    }

    private static function resetConfigCache(): void
    {
        $r = new \ReflectionClass(Config::class);
        if ($r->hasProperty('cache')) {
            $p = $r->getProperty('cache');
            $p->setAccessible(true);
            $p->setValue(null, null);
        }
    }

    private static function html(array $cfg, string $notice, string $error, int $localCount): string
    {
        $e = static function (string $v): string {
            return htmlspecialchars($v, ENT_QUOTES, 'UTF-8');
        };
        $enabled = !empty($cfg['enabled']) ? ' checked' : '';
        $pathStyle = !empty($cfg['path_style']) ? ' checked' : '';
        $forcePath = !empty($cfg['force_path']) ? ' checked' : '';
        $allowHttp = !empty($cfg['allow_http']) ? ' checked' : '';
        $endpoint = (string)($cfg['endpoint'] ?? '');
        $region = (string)($cfg['region'] ?? '');
        $bucket = (string)($cfg['bucket'] ?? '');
        $access = (string)($cfg['access_key'] ?? '');
        $publicBase = (string)($cfg['public_base'] ?? '');
        $prefix = (string)($cfg['prefix'] ?? '');

        $endpointHint = '';
        if ($endpoint !== '') {
            if (Client::validateEndpoint($endpoint, $cfg) === null) {
                $endpointHint = '<p class="s3-field-error">Endpoint must be a public https:// URL (no private/loopback hosts).</p>';
            } elseif (stripos($endpoint, 'https://') !== 0) {
                $endpointHint = '<p class="s3-field-warn">HTTP is unencrypted; intended for local testing only.</p>';
            }
        }

        $noticeHtml = $notice !== ''
            ? '<div class="s3-note" role="status">' . $e($notice) . '</div>'
            : '';
        $errorHtml = $error !== ''
            ? '<div class="s3-error" role="alert">' . $e($error) . '</div>'
            : '';
        $csrf = \Wawoo\Plugin\Admin\Csrf::field();

        return <<<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>S3 media settings - Admin</title>
<style>
body {
    margin: 0; min-height: 100vh; padding: 2rem 1rem;
    font-family: -apple-system, system-ui, "Segoe UI", "Helvetica Neue", sans-serif;
    background: #f6f7f9; color: #14161a;
}
.wrap { max-width: 640px; margin: 0 auto; }
a.back { font-size: .85rem; color: #3b5bdb; text-decoration: none; }
h1 { font-size: 1.4rem; margin: .4rem 0 .25rem; }
.hint { margin: 0 0 1rem; color: #6e6e73; font-size: .9rem; }
.card {
    background: #fff; border-radius: 14px; padding: 1.6rem 1.8rem;
    box-shadow: 0 12px 34px rgba(15,23,42,.08);
}
label { display: block; font-size: .85rem; font-weight: 600; margin: 1rem 0 .3rem; }
label.inline { display: flex; align-items: center; gap: .5rem; font-size: .95rem; margin-top: .9rem; }
input[type="text"], input[type="password"] {
    width: 100%; box-sizing: border-box;
    padding: .55rem .7rem; font-size: .95rem;
    border: 1px solid #d3d9e1; border-radius: 8px;
    background: #fff; color: inherit; font-family: inherit;
}
fieldset { border: 1px solid #e5e7eb; border-radius: 10px; margin: 1.25rem 0 0; padding: .4rem 1rem 1rem; }
legend { font-size: .85rem; font-weight: 600; padding: 0 .35rem; color: #6e6e73; }
button {
    margin-top: 1.4rem; border: 0; cursor: pointer;
    background: #3b5bdb; color: #fff; font-weight: 600;
    padding: .65rem 1.4rem; font-size: .95rem; border-radius: 8px;
}
button.sync { background: #0b7285; margin-left: .5rem; }
button:hover { filter: brightness(1.08); }
.s3-note {
    background: #e8f5e9; color: #1e7d32; border: 1px solid #a5d6a7;
    padding: .6rem .8rem; border-radius: 8px; margin-bottom: 1rem; font-size: .9rem;
}
.s3-error {
    background: #fdecea; color: #b3261e; border: 1px solid #ffb4ab;
    padding: .6rem .8rem; border-radius: 8px; margin-bottom: 1rem; font-size: .9rem;
}
.s3-field-error { margin: .35rem 0 0; color: #b3261e; font-size: .85rem; }
.s3-field-warn { margin: .35rem 0 0; color: #9a6700; font-size: .85rem; }
.count { margin: 1.25rem 0 0; padding-top: 1rem; border-top: 1px solid #e5e7eb; font-size: .9rem; color: #6e6e73; }
</style>
</head>
<body>
<div class="wrap">
    <a class="back" href="/admin/?action=plugins">&larr; Back to plugins</a>
    <h1>S3 media sync</h1>
    <p class="hint">Mirror post/page/upload media to an S3-compatible bucket and serve it from the public base URL.</p>
    <div class="card">
        {$noticeHtml}
        {$errorHtml}
        <form method="post" action="/admin/?action=settings&amp;plugin=s3">
            {$csrf}
            <label class="inline"><input type="checkbox" name="enabled" value="1"{$enabled}> Enable media sync &amp; URL rewriting</label>
            <label for="s3-endpoint">Endpoint</label>
            <input type="text" id="s3-endpoint" name="endpoint" value="{$e($endpoint)}" placeholder="https://s3.amazonaws.com">
            {$endpointHint}
            <label class="inline"><input type="checkbox" name="allow_http" value="1"{$allowHttp}> Allow HTTP (insecure, local testing)</label>
            <label for="s3-region">Region</label>
            <input type="text" id="s3-region" name="region" value="{$e($region)}" placeholder="us-east-1">
            <label for="s3-bucket">Bucket</label>
            <input type="text" id="s3-bucket" name="bucket" value="{$e($bucket)}" placeholder="my-bucket">
            <label for="s3-access">Access key ID</label>
            <input type="text" id="s3-access" name="access_key" value="{$e($access)}" autocomplete="off">
            <label for="s3-secret">Secret access key</label>
            <input type="password" id="s3-secret" name="secret_key" autocomplete="new-password" placeholder="Leave blank to keep the current secret">
            <label for="s3-public">Public base URL</label>
            <input type="text" id="s3-public" name="public_base" value="{$e($publicBase)}" placeholder="https://cdn.example.com/media">
            <label for="s3-prefix">Object key prefix</label>
            <input type="text" id="s3-prefix" name="prefix" value="{$e($prefix)}" placeholder="media">
            <label class="inline"><input type="checkbox" name="path_style" value="1"{$pathStyle}> Path-style requests (endpoint/bucket/key)</label>
            <label class="inline"><input type="checkbox" name="force_path" value="1"{$forcePath}> Force re-upload of every file on sync</label>
            <input type="hidden" name="action" value="save">
            <button type="submit">Save settings</button>
            <button class="sync" type="submit" name="action" value="sync">Save &amp; sync now</button>
        </form>
        <p class="count">Media files discovered locally: {$localCount}</p>
    </div>
</div>
</body>
</html>
HTML;
    }
}
