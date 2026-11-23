<?php

declare(strict_types=1);

namespace PhpIssuesChecker\Check;

use PhpIssuesChecker\Data\AdvisoryData;
use PhpIssuesChecker\Environment;
use PhpIssuesChecker\Finding;
use PhpIssuesChecker\VersionRange;

/**
 * Matches the running PHP version, extensions and SAPI against the
 * official php/php-src GitHub security advisories.
 */
final class KnownVulnerabilitiesCheck implements Check
{
    /** advisory "sapi-<x>" component => PHP_SAPI value */
    private const SAPIS = [
        'sapi-fpm' => 'fpm-fcgi',
        'sapi-cgi' => 'cgi-fcgi',
        'sapi-cli' => 'cli',
        'sapi-cli-server' => 'cli-server',
        'sapi-apache2' => 'apache2handler',
        'sapi-apache2handler' => 'apache2handler',
        'sapi-litespeed' => 'litespeed',
        'sapi-phpdbg' => 'phpdbg',
    ];

    private const SAPI_LABELS = [
        'sapi-fpm' => 'PHP-FPM',
        'sapi-cgi' => 'PHP-CGI',
        'sapi-cli-server' => 'the built-in web server (php -S)',
        'sapi-apache2' => 'Apache mod_php',
        'sapi-apache2handler' => 'Apache mod_php',
        'sapi-litespeed' => 'LiteSpeed',
        'sapi-phpdbg' => 'phpdbg',
    ];

    /** Extensions that are compiled into every PHP build and cannot be disabled. */
    private const ALWAYS_LOADED = ['core', 'standard', 'date', 'pcre', 'spl', 'reflection', 'hash', 'random'];

    public function name(): string
    {
        return 'vulnerabilities';
    }

    public function run(Environment $env, AdvisoryData $data): array
    {
        $version = $env->phpVersion();
        $findings = [];

        foreach ($data->advisories as $advisory) {
            foreach ($advisory['affected'] as $affected) {
                if (!VersionRange::matches($version, $affected['range'])) {
                    continue;
                }
                $condition = $this->applies($env, $affected['component']);
                if ($condition === false) {
                    continue;
                }

                $findings[] = $this->finding($env, $data, $advisory, $affected, $condition);
                break; // one finding per advisory
            }
        }

        return $findings;
    }

    /**
     * @return bool|string true = affects you, false = does not,
     *                     string = affects you only under this condition
     */
    private function applies(Environment $env, string $component)
    {
        if (strpos($component, 'ext-') === 0) {
            $extension = substr($component, 4);
            if (in_array($extension, self::ALWAYS_LOADED, true)) {
                return true;
            }
            if (!$env->knowsExtensions()) {
                return sprintf('only if the "%s" extension is enabled', $extension);
            }

            return $env->hasExtension($extension);
        }

        if (strpos($component, 'sapi-') === 0) {
            $label = self::SAPI_LABELS[$component] ?? substr($component, 5);
            $sapi = self::SAPIS[$component] ?? null;
            if ($sapi !== null && $env->sapi() === $sapi) {
                return true;
            }

            // Composer/CI run the CLI; the web server may use another SAPI.
            return sprintf('only if your site runs on %s', $label);
        }

        return true;
    }

    /**
     * @param array<string, mixed> $advisory
     * @param array<string, string> $affected
     * @param bool|string $condition
     */
    private function finding(Environment $env, AdvisoryData $data, array $advisory, array $affected, $condition): Finding
    {
        $branch = $env->branch();
        $fixedIn = $this->patchedInBranch($affected['patched'], $branch);

        if ($fixedIn !== null) {
            $latest = $data->latest[$branch] ?? null;
            $fix = [sprintf(
                'Upgrade PHP to %s or later%s.',
                $fixedIn,
                $latest !== null && version_compare($latest, $fixedIn, '>') ? sprintf(' (latest %s release: %s)', $branch, $latest) : ''
            )];
        } else {
            $target = $data->newestSupportedBranch();
            $fix = [sprintf(
                'The advisory lists no fix for PHP %s. Upgrade to a supported branch%s.',
                $branch,
                $target !== null ? sprintf(', ideally PHP %s (%s)', $target, $data->latest[$target] ?? $target) : ''
            )];
        }

        if (is_string($condition)) {
            $fix[] = sprintf('This advisory applies %s; if that is not your setup you can ignore it.', $condition);
        }

        $title = $advisory['summary'] !== '' ? $advisory['summary'] : 'Security vulnerability in PHP';
        if (is_string($condition)) {
            $title .= ' (' . $condition . ')';
        }

        $finding = new Finding(
            'vulnerabilities',
            $advisory['severity'],
            $advisory['cve'] ?? $advisory['id'],
            $title,
            sprintf(
                'Affects %s %s; you run %s.%s',
                $affected['component'] === 'core' ? 'PHP' : $affected['component'],
                $affected['range'],
                $env->phpVersion(),
                $advisory['cve'] !== null ? ' Advisory ' . $advisory['id'] . '.' : ''
            ),
            $fix,
            $advisory['url']
        );
        $finding->fixedIn = $fixedIn;

        return $finding;
    }

    private function patchedInBranch(string $patched, string $branch): ?string
    {
        foreach (preg_split('/[\s,|]+/', $patched) ?: [] as $candidate) {
            $candidate = ltrim($candidate, '>=v');
            if (preg_match('/^(\d+\.\d+)\.\d+$/', $candidate, $m) && $m[1] === $branch) {
                return $candidate;
            }
        }

        return null;
    }
}
