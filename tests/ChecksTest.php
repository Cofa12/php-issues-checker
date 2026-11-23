<?php

declare(strict_types=1);

namespace PhpIssuesChecker\Tests;

use PhpIssuesChecker\Check\IniSettingsCheck;
use PhpIssuesChecker\Check\KnownVulnerabilitiesCheck;
use PhpIssuesChecker\Check\VersionSupportCheck;
use PhpIssuesChecker\Checker;
use PhpIssuesChecker\Data\AdvisoryData;
use PhpIssuesChecker\Data\DataProvider;
use PhpIssuesChecker\Environment;
use PhpIssuesChecker\Finding;
use PhpIssuesChecker\Options;
use PhpIssuesChecker\Report\JsonReporter;
use PhpIssuesChecker\Report\TextReporter;
use PHPUnit\Framework\TestCase;

final class ChecksTest extends TestCase
{
    private function data(): AdvisoryData
    {
        return (new DataProvider(true, null, 0, null, __DIR__ . '/Fixtures/snapshot.json'))->load();
    }

    /** @param string[] $extensions */
    private function env(string $version, string $sapi = 'cli', array $extensions = ['core', 'standard'], ?array $ini = []): Environment
    {
        return new Environment($version, $sapi, $extensions, $ini, '/etc/php.ini');
    }

    /** @param Finding[] $findings @return string[] */
    private function ids(array $findings): array
    {
        return array_map(static function (Finding $f): string {
            return $f->id;
        }, $findings);
    }

    public function testEndOfLifeBranchIsCritical(): void
    {
        $findings = (new VersionSupportCheck(new \DateTimeImmutable('2026-11-23')))->run($this->env('8.1.30'), $this->data());

        self::assertSame(['php-branch-eol'], $this->ids($findings));
        self::assertSame(Finding::CRITICAL, $findings[0]->severity);
        self::assertStringContainsString('8.5', $findings[0]->fix[0]);
    }

    public function testBranchOlderThanAnyKnownIsEndOfLife(): void
    {
        $findings = (new VersionSupportCheck())->run($this->env('5.6.40'), $this->data());

        self::assertSame(['php-branch-eol'], $this->ids($findings));
    }

    public function testSecurityOnlyBranchEndingSoonIsMedium(): void
    {
        $findings = (new VersionSupportCheck(new \DateTimeImmutable('2026-11-23')))->run($this->env('8.2.36'), $this->data());

        self::assertSame(['php-branch-security-only'], $this->ids($findings));
        self::assertSame(Finding::MEDIUM, $findings[0]->severity);
    }

    public function testOutdatedPatchAndUpToDate(): void
    {
        $check = new VersionSupportCheck(new \DateTimeImmutable('2026-11-23'));

        self::assertSame(['php-patch-outdated'], $this->ids($check->run($this->env('8.4.15'), $this->data())));
        self::assertSame([], $check->run($this->env('8.4.28'), $this->data()));
    }

    public function testUnreleasedBranchIsInfo(): void
    {
        $findings = (new VersionSupportCheck())->run($this->env('9.0.0'), $this->data());

        self::assertSame(['php-branch-unknown'], $this->ids($findings));
    }

    public function testVulnerabilitiesRespectExtensionsAndSapi(): void
    {
        $check = new KnownVulnerabilitiesCheck();

        // CLI without soap: core CVE + FPM CVE (conditional, since the web SAPI is unknown)
        $findings = $check->run($this->env('8.4.15'), $this->data());
        self::assertSame(['CVE-2026-0001', 'GHSA-fpm-0003'], $this->ids($findings));
        self::assertSame('8.4.27', $findings[0]->fixedIn);
        self::assertStringContainsString('only if your site runs on PHP-FPM', $findings[1]->title);

        // With soap loaded
        $withSoap = $check->run($this->env('8.4.15', 'cli', ['core', 'soap']), $this->data());
        self::assertContains('CVE-2026-0002', $this->ids($withSoap));

        // Running under FPM: definite, no condition in the title
        $fpm = $check->run($this->env('8.4.15', 'fpm-fcgi'), $this->data());
        self::assertSame('FPM bug', $fpm[1]->title);

        // Fixed version: nothing
        self::assertSame([], $check->run($this->env('8.4.28', 'cli', ['core', 'soap']), $this->data()));
    }

    public function testVulnerabilityWithoutFixInBranchRecommendsNewBranch(): void
    {
        $findings = (new KnownVulnerabilitiesCheck())->run($this->env('8.1.2'), $this->data());

        self::assertSame(['CVE-2026-0001'], $this->ids($findings));
        self::assertNull($findings[0]->fixedIn);
        self::assertStringContainsString('PHP 8.5', $findings[0]->fix[0]);
    }

    public function testIniRules(): void
    {
        $ini = [
            'allow_url_include' => '1',
            'display_errors' => 'stderr',
            'expose_php' => 'Off',
            'log_errors' => '1',
            'session.use_strict_mode' => '0',
            'session.cookie_samesite' => 'Lax',
            'disable_functions' => 'exec',
            'open_basedir' => '/var/www',
            'allow_url_fopen' => '0',
            'zend.assertions' => '-1',
        ];

        $noSession = (new IniSettingsCheck())->run($this->env('8.4.28', 'cli', ['core'], $ini), $this->data());
        self::assertSame(['allow_url_include'], $this->ids($noSession));
        self::assertSame(Finding::CRITICAL, $noSession[0]->severity);

        $withSession = (new IniSettingsCheck())->run($this->env('8.4.28', 'cli', ['core', 'session'], $ini), $this->data());
        self::assertSame(['allow_url_include', 'session.use_strict_mode'], $this->ids($withSession));

        self::assertSame([], (new IniSettingsCheck())->run(Environment::forVersion('8.4.0'), $this->data()));
    }

    public function testCheckerIgnoreSkipAndFailOn(): void
    {
        $provider = new DataProvider(true, null, 0, null, __DIR__ . '/Fixtures/snapshot.json');
        $options = Options::fromArray(['fail-on' => 'critical', 'ignore' => ['CVE-2026-0001'], 'skip' => ['ini', 'version']]);

        $report = (new Checker($provider))->run($options, $this->env('8.4.15'));

        self::assertSame(['GHSA-fpm-0003'], $this->ids($report->findings));
        self::assertSame(1, $report->ignored);
        self::assertFalse($report->hasAtLeast($options->failOn));
        self::assertTrue($report->hasAtLeast('medium'));
        self::assertFalse($report->hasAtLeast('none'));
    }

    public function testReportersRender(): void
    {
        $provider = new DataProvider(true, null, 0, null, __DIR__ . '/Fixtures/snapshot.json');
        $report = (new Checker($provider))->run(null, $this->env('8.4.15', 'cli', ['core'], ['display_errors' => '1']));

        $full = implode("\n", (new TextReporter())->render($report));
        self::assertStringContainsString('CVE-2026-0001', $full);
        self::assertStringContainsString('How to upgrade PHP', $full);

        $compact = implode("\n", (new TextReporter(true))->render($report));
        self::assertStringContainsString('2 known security vulnerabilities affect PHP 8.4.15', $compact);
        self::assertStringContainsString('upgrade PHP to 8.4.28', $compact);

        $json = json_decode((new JsonReporter())->render($report), true);
        self::assertSame(4, $json['summary']['total']);
        self::assertSame('bundled snapshot', $json['data']['source']);
    }

    public function testInvalidFailOnIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Options::fromArray(['fail-on' => 'urgent']);
    }

    public function testNormalizeVersion(): void
    {
        self::assertSame('8.4.15', Environment::normalizeVersion('8.4.15-1ubuntu2'));
        self::assertSame('8.3.0', Environment::normalizeVersion('8.3'));
    }
}
