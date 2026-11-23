<?php

declare(strict_types=1);

namespace PhpIssuesChecker\Check;

use PhpIssuesChecker\Data\AdvisoryData;
use PhpIssuesChecker\Environment;
use PhpIssuesChecker\Finding;

/**
 * Is this PHP branch still supported by the PHP project, and is it on
 * the latest patch release? Source: php.net/supported-versions.
 */
final class VersionSupportCheck implements Check
{
    private const SUPPORT_URL = 'https://www.php.net/supported-versions.php';

    /** Warn this many days before security support ends. */
    private const ENDING_SOON_DAYS = 180;

    private \DateTimeImmutable $today;

    public function __construct(?\DateTimeImmutable $today = null)
    {
        $this->today = $today ?? new \DateTimeImmutable('today', new \DateTimeZone('UTC'));
    }

    public function name(): string
    {
        return 'version';
    }

    public function run(Environment $env, AdvisoryData $data): array
    {
        $version = $env->phpVersion();
        $branch = $env->branch();
        $target = $data->newestSupportedBranch();
        $targetLatest = $target !== null ? ($data->latest[$target] ?? $target) : null;
        $upgradeStep = $target !== null
            ? sprintf('Upgrade to a supported branch, ideally PHP %s (latest release: %s).', $target, $targetLatest)
            : 'Upgrade to a supported PHP branch (see php.net/supported-versions).';

        $info = $data->branches[$branch] ?? null;

        if ($info === null) {
            $oldest = $this->oldestKnownBranch($data);
            if ($oldest !== null && version_compare($branch, $oldest, '<')) {
                return [$this->endOfLife($branch, $version, null, $upgradeStep)];
            }

            return [new Finding(
                'version',
                Finding::INFO,
                'php-branch-unknown',
                sprintf('PHP %s is not listed on php.net yet', $branch),
                sprintf('You run PHP %s, which is newer than any branch php.net lists (pre-release or development build). Its security status cannot be checked.', $version),
                ['Do not use pre-release PHP builds in production.'],
                self::SUPPORT_URL
            )];
        }

        $state = $info['state'] ?? 'unknown';
        $securityEnd = $info['security_support_end'] ?? null;

        if ($state === 'eol' || ($securityEnd !== null && $this->isPast($securityEnd))) {
            return [$this->endOfLife($branch, $version, $securityEnd, $upgradeStep)];
        }

        $findings = [];

        if ($state === 'security') {
            $endingSoon = $securityEnd !== null && $this->daysUntil($securityEnd) <= self::ENDING_SOON_DAYS;
            $findings[] = new Finding(
                'version',
                $endingSoon ? Finding::MEDIUM : Finding::LOW,
                'php-branch-security-only',
                sprintf('PHP %s only receives security fixes%s', $branch, $securityEnd ? ' until ' . $securityEnd : ''),
                sprintf(
                    'Active support for PHP %s ended%s. It no longer gets bug fixes, and after %s it gets no security fixes either.',
                    $branch,
                    isset($info['active_support_end']) ? ' on ' . $info['active_support_end'] : '',
                    $securityEnd ?? 'its end-of-life date'
                ),
                [
                    $upgradeStep,
                    sprintf('Plan the upgrade before %s; run your test suite on the new version first.', $securityEnd ?? 'end of life'),
                ],
                self::SUPPORT_URL
            );
        }

        $latest = $data->latest[$branch] ?? null;
        if ($latest !== null && version_compare($version, $latest, '<')) {
            $findings[] = new Finding(
                'version',
                Finding::MEDIUM,
                'php-patch-outdated',
                sprintf('PHP %s is not the latest %s release (%s)', $version, $branch, $latest),
                'Patch releases contain bug and security fixes and are safe to install: they do not break compatibility.',
                [sprintf('Update PHP to %s (same branch, drop-in upgrade).', $latest)],
                'https://www.php.net/ChangeLog-' . strtok($branch, '.') . '.php'
            );
        }

        return $findings;
    }

    private function endOfLife(string $branch, string $version, ?string $securityEnd, string $upgradeStep): Finding
    {
        return new Finding(
            'version',
            Finding::CRITICAL,
            'php-branch-eol',
            sprintf('PHP %s is end-of-life%s', $branch, $securityEnd ? ' since ' . $securityEnd : ''),
            sprintf(
                'You run PHP %s. The PHP project no longer releases security fixes for %s, so newly found vulnerabilities will never be fixed.',
                $version,
                $branch
            ),
            [
                $upgradeStep,
                'Check your dependencies allow it: composer why-not php <version>',
                'If you cannot upgrade yet, use a vendor that provides extended support (e.g. your Linux distribution LTS packages) and keep the server off the public internet where possible.',
            ],
            self::SUPPORT_URL
        );
    }

    private function oldestKnownBranch(AdvisoryData $data): ?string
    {
        $oldest = null;
        foreach (array_keys($data->branches) as $branch) {
            if ($oldest === null || version_compare((string) $branch, $oldest, '<')) {
                $oldest = (string) $branch;
            }
        }

        return $oldest;
    }

    private function isPast(string $date): bool
    {
        return $this->daysUntil($date) < 0;
    }

    private function daysUntil(string $date): int
    {
        $end = new \DateTimeImmutable($date, new \DateTimeZone('UTC'));
        $diff = $this->today->diff($end);

        return (int) $diff->format('%r%a');
    }
}
