<?php

declare(strict_types=1);

namespace PhpIssuesChecker;

use PhpIssuesChecker\Data\AdvisoryData;

final class Report
{
    public Environment $environment;

    public AdvisoryData $data;

    /** @var Finding[] Sorted most severe first */
    public array $findings;

    /** @var int Findings hidden by the ignore list */
    public int $ignored;

    /** @param Finding[] $findings */
    public function __construct(Environment $environment, AdvisoryData $data, array $findings, int $ignored = 0)
    {
        usort($findings, static function (Finding $a, Finding $b): int {
            return Finding::rank($b->severity) <=> Finding::rank($a->severity);
        });

        $this->environment = $environment;
        $this->data = $data;
        $this->findings = $findings;
        $this->ignored = $ignored;
    }

    /** @return array<string, int> severity => count, most severe first */
    public function counts(): array
    {
        $counts = array_fill_keys(Finding::severities(), 0);
        foreach ($this->findings as $finding) {
            $counts[$finding->severity]++;
        }

        return $counts;
    }

    public function hasAtLeast(string $severity): bool
    {
        if ($severity === 'none') {
            return false;
        }
        foreach ($this->findings as $finding) {
            if ($finding->isAtLeast($severity)) {
                return true;
            }
        }

        return false;
    }

    /** True when the user should upgrade PHP (EOL branch, old patch or known CVEs). */
    public function needsUpgrade(): bool
    {
        foreach ($this->findings as $finding) {
            if ($finding->check === 'vulnerabilities' || in_array($finding->id, ['php-branch-eol', 'php-patch-outdated', 'php-branch-security-only'], true)) {
                return true;
            }
        }

        return false;
    }
}
