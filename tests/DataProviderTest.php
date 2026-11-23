<?php

declare(strict_types=1);

namespace PhpIssuesChecker\Tests;

use PhpIssuesChecker\Data\AdvisoryData;
use PhpIssuesChecker\Data\DataProvider;
use PhpIssuesChecker\Data\HttpClient;
use PHPUnit\Framework\TestCase;

final class DataProviderTest extends TestCase
{
    private string $cacheDir;

    protected function setUp(): void
    {
        $this->cacheDir = sys_get_temp_dir() . '/pic-test-' . bin2hex(random_bytes(4));
        mkdir($this->cacheDir);
    }

    protected function tearDown(): void
    {
        @unlink($this->cacheDir . '/php-issues-checker-data.json');
        @rmdir($this->cacheDir);
    }

    public function testFallsBackToBundledSnapshotWhenOffline(): void
    {
        $failing = new class () extends HttpClient {
            public function getJson(string $url, array $headers = [])
            {
                throw new \RuntimeException('no network');
            }
        };

        $data = (new DataProvider(false, $this->cacheDir, 86400, $failing, __DIR__ . '/Fixtures/snapshot.json'))->load();

        self::assertSame(AdvisoryData::SOURCE_BUNDLED, $data->source);
        self::assertStringContainsString('no network', (string) $data->warning);
    }

    public function testLiveDataIsNormalizedAndCached(): void
    {
        $fake = new class () extends HttpClient {
            public int $calls = 0;

            public function getJson(string $url, array $headers = [])
            {
                $this->calls++;
                if (strpos($url, 'states.php') !== false) {
                    return ['8' => ['8.4' => ['state' => 'stable', 'security_support_end' => '2028-12-31T00:00:00+00:00']]];
                }
                if (strpos($url, 'releases/index.php') !== false) {
                    return ['8.4.28' => [], '8.4.3' => [], '8.3.37' => []];
                }

                return [
                    ['ghsa_id' => 'GHSA-a', 'cve_id' => 'CVE-1', 'severity' => 'high', 'summary' => 'x', 'html_url' => 'u', 'published_at' => '2026-01-02T00:00:00Z', 'state' => 'published',
                        'vulnerabilities' => [['package' => ['name' => 'PHP-FPM'], 'vulnerable_version_range' => '< 8.4.28', 'patched_versions' => '8.4.28']]],
                    ['ghsa_id' => 'GHSA-b', 'withdrawn_at' => '2026-01-01', 'vulnerabilities' => []],
                ];
            }
        };

        $provider = new DataProvider(false, $this->cacheDir, 86400, $fake);
        $data = $provider->load();

        self::assertSame(AdvisoryData::SOURCE_LIVE, $data->source);
        self::assertSame('8.4.28', $data->latest['8.4']);
        self::assertSame('2028-12-31', $data->branches['8.4']['security_support_end']);
        self::assertCount(1, $data->advisories);
        self::assertSame('sapi-fpm', $data->advisories[0]['affected'][0]['component']);

        $calls = $fake->calls;
        self::assertSame(AdvisoryData::SOURCE_CACHE, $provider->load()->source);
        self::assertSame($calls, $fake->calls, 'second load must come from cache');
    }

    public function testBundledSnapshotShipsWithPackage(): void
    {
        $data = (new DataProvider(true))->load();

        self::assertNotEmpty($data->advisories);
        self::assertNotNull($data->newestSupportedBranch());
    }
}
