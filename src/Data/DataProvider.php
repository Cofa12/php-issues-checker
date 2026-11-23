<?php

declare(strict_types=1);

namespace PhpIssuesChecker\Data;

/**
 * Loads official PHP data: live from php.net and the php/php-src GitHub
 * security advisories, cached for a day, falling back to the snapshot
 * shipped inside the package when offline.
 */
class DataProvider
{
    public const STATES_URL = 'https://www.php.net/releases/states.php';
    public const RELEASES_URL = 'https://www.php.net/releases/index.php?json&max=1000&version=';
    public const ADVISORIES_URL = 'https://api.github.com/repos/php/php-src/security-advisories?per_page=100&page=';

    private bool $offline;

    private string $cacheFile;

    private int $ttl;

    private HttpClient $http;

    private string $snapshotFile;

    public function __construct(
        bool $offline = false,
        ?string $cacheDir = null,
        int $ttl = 86400,
        ?HttpClient $http = null,
        ?string $snapshotFile = null
    ) {
        $this->offline = $offline;
        $this->cacheFile = rtrim($cacheDir ?? sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'php-issues-checker-data.json';
        $this->ttl = $ttl;
        $this->http = $http ?? new HttpClient();
        $this->snapshotFile = $snapshotFile ?? dirname(__DIR__, 2) . '/data/snapshot.json';
    }

    public function load(): AdvisoryData
    {
        if ($this->offline) {
            return $this->bundled();
        }

        $cached = $this->readCache();
        if ($cached !== null && $this->cacheIsFresh()) {
            return AdvisoryData::fromArray($cached, AdvisoryData::SOURCE_CACHE);
        }

        try {
            $data = $this->fetchLive();
            $this->writeCache($data->toArray());

            return $data;
        } catch (\Throwable $e) {
            $fallback = $cached !== null
                ? AdvisoryData::fromArray($cached, AdvisoryData::SOURCE_CACHE)
                : $this->bundled();
            $fallback->warning = 'Could not download the latest data (' . $e->getMessage() . '); using ' . $fallback->source . ' from ' . $fallback->generatedAt . '.';

            return $fallback;
        }
    }

    public function bundled(): AdvisoryData
    {
        $raw = @file_get_contents($this->snapshotFile);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($data)) {
            throw new \RuntimeException('The bundled data snapshot is missing or corrupt: ' . $this->snapshotFile);
        }

        return AdvisoryData::fromArray($data, AdvisoryData::SOURCE_BUNDLED);
    }

    public function fetchLive(): AdvisoryData
    {
        $branches = $this->fetchBranches();
        $latest = $this->fetchLatestReleases(array_keys($branches));
        $advisories = $this->fetchAdvisories();

        return new AdvisoryData($branches, $latest, $advisories, gmdate('Y-m-d\TH:i:s\Z'), AdvisoryData::SOURCE_LIVE);
    }

    /** @return array<string, array<string, mixed>> */
    private function fetchBranches(): array
    {
        $states = $this->http->getJson(self::STATES_URL);
        $branches = [];
        foreach ($states as $majorBranches) {
            if (!is_array($majorBranches)) {
                continue;
            }
            foreach ($majorBranches as $branch => $info) {
                $branches[(string) $branch] = [
                    'state' => (string) ($info['state'] ?? 'unknown'),
                    'initial_release' => self::date($info['initial_release'] ?? null),
                    'active_support_end' => self::date($info['active_support_end'] ?? null),
                    'security_support_end' => self::date($info['security_support_end'] ?? null),
                ];
            }
        }
        if ($branches === []) {
            throw new \RuntimeException('php.net returned no branch data.');
        }
        uksort($branches, static function ($a, $b): int {
            return version_compare((string) $b, (string) $a);
        });

        return $branches;
    }

    /**
     * @param string[] $branches
     *
     * @return array<string, string>
     */
    private function fetchLatestReleases(array $branches): array
    {
        $majors = [];
        foreach ($branches as $branch) {
            $majors[(int) $branch] = true;
        }

        $latest = [];
        foreach (array_keys($majors) as $major) {
            if ($major < 5) {
                continue;
            }
            $releases = $this->http->getJson(self::RELEASES_URL . $major);
            foreach (array_keys($releases) as $version) {
                $version = (string) $version;
                if (!preg_match('/^(\d+\.\d+)\.\d+$/', $version, $m)) {
                    continue;
                }
                if (!isset($latest[$m[1]]) || version_compare($version, $latest[$m[1]], '>')) {
                    $latest[$m[1]] = $version;
                }
            }
        }
        uksort($latest, static function ($a, $b): int {
            return version_compare((string) $b, (string) $a);
        });

        return $latest;
    }

    /** @return list<array<string, mixed>> */
    private function fetchAdvisories(): array
    {
        $headers = [
            'Accept' => 'application/vnd.github+json',
            'X-GitHub-Api-Version' => '2022-11-28',
        ];
        $token = getenv('GITHUB_TOKEN');
        if (is_string($token) && $token !== '') {
            $headers['Authorization'] = 'Bearer ' . $token;
        }

        $advisories = [];
        for ($page = 1; $page <= 20; $page++) {
            $batch = $this->http->getJson(self::ADVISORIES_URL . $page, $headers);
            foreach ($batch as $raw) {
                if (is_array($raw) && ($normalized = self::normalizeAdvisory($raw)) !== null) {
                    $advisories[] = $normalized;
                }
            }
            if (count($batch) < 100) {
                break;
            }
        }

        usort($advisories, static function (array $a, array $b): int {
            return strcmp((string) $b['published'], (string) $a['published']);
        });

        return $advisories;
    }

    /**
     * @param array<string, mixed> $raw GitHub repository security advisory
     *
     * @return array<string, mixed>|null
     */
    public static function normalizeAdvisory(array $raw): ?array
    {
        if (!empty($raw['withdrawn_at']) || ($raw['state'] ?? 'published') !== 'published') {
            return null;
        }

        $affected = [];
        foreach ($raw['vulnerabilities'] ?? [] as $vulnerability) {
            $range = trim((string) ($vulnerability['vulnerable_version_range'] ?? ''));
            if ($range === '') {
                continue;
            }
            $affected[] = [
                'component' => self::normalizeComponent((string) ($vulnerability['package']['name'] ?? '')),
                'range' => $range,
                'patched' => trim((string) ($vulnerability['patched_versions'] ?? '')),
            ];
        }
        if ($affected === []) {
            return null;
        }

        return [
            'id' => (string) $raw['ghsa_id'],
            'cve' => isset($raw['cve_id']) && $raw['cve_id'] !== '' ? (string) $raw['cve_id'] : null,
            'severity' => strtolower((string) ($raw['severity'] ?? 'medium')) ?: 'medium',
            'summary' => trim((string) ($raw['summary'] ?? '')),
            'url' => (string) ($raw['html_url'] ?? ('https://github.com/php/php-src/security/advisories/' . $raw['ghsa_id'])),
            'published' => self::date($raw['published_at'] ?? null),
            'affected' => $affected,
        ];
    }

    /**
     * Maps the free-form package names used in php-src advisories to
     * "core", "ext-<name>" or "sapi-<name>".
     */
    public static function normalizeComponent(string $name): string
    {
        $name = strtolower(trim($name));
        if (in_array($name, ['', 'php', 'php-src', 'engine', 'core', 'zend'], true)) {
            return 'core';
        }
        if ($name === 'php-fpm' || $name === 'fpm') {
            return 'sapi-fpm';
        }
        if ($name === 'php-cgi' || $name === 'cgi') {
            return 'sapi-cgi';
        }

        return $name;
    }

    private static function date(?string $value): ?string
    {
        return $value === null || $value === '' ? null : substr($value, 0, 10);
    }

    /** @return array<string, mixed>|null */
    private function readCache(): ?array
    {
        if (!is_file($this->cacheFile)) {
            return null;
        }
        $data = json_decode((string) @file_get_contents($this->cacheFile), true);

        return is_array($data) && isset($data['branches'], $data['latest'], $data['advisories'], $data['generated_at']) ? $data : null;
    }

    private function cacheIsFresh(): bool
    {
        $mtime = @filemtime($this->cacheFile);

        return $mtime !== false && (time() - $mtime) < $this->ttl;
    }

    /** @param array<string, mixed> $data */
    private function writeCache(array $data): void
    {
        $json = json_encode($data, JSON_UNESCAPED_SLASHES);
        if ($json !== false) {
            @file_put_contents($this->cacheFile, $json, LOCK_EX);
        }
    }
}
