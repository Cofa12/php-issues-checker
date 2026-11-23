<?php

declare(strict_types=1);

namespace PhpIssuesChecker\Report;

use PhpIssuesChecker\Finding;
use PhpIssuesChecker\Report;

/**
 * Human-readable report. Lines use Symfony console tags (<error>, <comment>,
 * <info>) so Composer can colour them; the CLI converts or strips them.
 */
final class TextReporter
{
    private const TAGS = [
        Finding::CRITICAL => 'error',
        Finding::HIGH => 'error',
        Finding::MEDIUM => 'comment',
        Finding::LOW => 'comment',
        Finding::INFO => 'info',
    ];

    /** In compact mode, CVEs below this severity are counted but not listed. */
    private const COMPACT_LIST_FROM = Finding::HIGH;

    private bool $compact;

    /**
     * @param bool $compact Group CVEs and print one line per issue (used by the Composer plugin)
     */
    public function __construct(bool $compact = false)
    {
        $this->compact = $compact;
    }

    /** @return string[] */
    public function render(Report $report): array
    {
        $env = $report->environment;
        $data = $report->data;
        $lines = [];

        $lines[] = sprintf(
            '<info>PHP Issues Checker</info>: PHP %s (%s)%s',
            $env->phpVersion(),
            $env->sapi(),
            $env->iniFile() !== null ? ', php.ini: ' . $env->iniFile() : ''
        );
        $lines[] = sprintf(
            'Official data: php.net + php/php-src security advisories (%s, %s, %d advisories)',
            $data->source,
            substr($data->generatedAt, 0, 10),
            count($data->advisories)
        );
        if ($data->warning !== null) {
            $lines[] = '<comment>' . $data->warning . '</comment>';
        }
        $lines[] = '';

        if ($report->findings === []) {
            $lines[] = '<info>No known issues found.</info>' . ($report->ignored > 0 ? sprintf(' (%d ignored)', $report->ignored) : '');

            return $lines;
        }

        if ($this->compact) {
            return array_merge($lines, $this->renderCompact($report));
        }

        foreach ($report->findings as $finding) {
            $tag = self::TAGS[$finding->severity];
            $lines[] = sprintf('<%s>[%s]</%s> %s  %s', $tag, strtoupper($finding->severity), $tag, $finding->id, $finding->title);
            $lines[] = '    ' . $finding->details;
            foreach ($finding->fix as $i => $step) {
                $lines[] = sprintf('    %s %s', count($finding->fix) > 1 ? ($i + 1) . '.' : 'Fix:', $step);
            }
            if ($finding->url !== null) {
                $lines[] = '    More: ' . $finding->url;
            }
            $lines[] = '';
        }

        if ($report->needsUpgrade()) {
            $lines[] = '<info>How to upgrade PHP</info>';
            foreach (UpgradeGuide::steps($env->branch(), $data->newestSupportedBranch()) as $platform => $step) {
                $lines[] = sprintf('  - %s: %s', $platform, $step);
            }
            $lines[] = '';
        }

        if ($env->sapi() === 'cli') {
            $lines[] = 'Note: this checked the command-line PHP. Your web server may run a different PHP version or php.ini; check it too (see README: "Checking the web server PHP").';
        }
        $lines[] = 'Dependencies: run "composer audit" to check your Composer packages for advisories.';
        $lines[] = '';
        $lines[] = $this->summary($report);

        return $lines;
    }

    /** @return string[] */
    private function renderCompact(Report $report): array
    {
        $env = $report->environment;
        $data = $report->data;
        $lines = [];

        $vulnerabilities = array_values(array_filter($report->findings, static function (Finding $f): bool {
            return $f->check === 'vulnerabilities';
        }));

        if ($vulnerabilities !== []) {
            $counts = [];
            $fixedIn = null;
            $fixedInBranch = 0;
            foreach ($vulnerabilities as $f) {
                $counts[$f->severity] = ($counts[$f->severity] ?? 0) + 1;
                if ($f->fixedIn !== null) {
                    $fixedInBranch++;
                    if ($fixedIn === null || version_compare($f->fixedIn, $fixedIn, '>')) {
                        $fixedIn = $f->fixedIn;
                    }
                }
            }
            $unfixed = count($vulnerabilities) - $fixedInBranch;
            $worst = $vulnerabilities[0]->severity; // findings are sorted
            $tag = self::TAGS[$worst];
            $parts = [];
            foreach (Finding::severities() as $severity) {
                if (isset($counts[$severity])) {
                    $parts[] = $counts[$severity] . ' ' . $severity;
                }
            }
            $lines[] = sprintf(
                '<%s>[%s]</%s> %d known security vulnerabilit%s affect PHP %s (%s)',
                $tag,
                strtoupper($worst),
                $tag,
                count($vulnerabilities),
                count($vulnerabilities) === 1 ? 'y' : 'ies',
                $env->phpVersion(),
                implode(', ', $parts)
            );

            $latest = $data->latest[$env->branch()] ?? $fixedIn;
            $target = $data->newestSupportedBranch();
            $targetText = ($target ?? 'a supported branch')
                . ($target !== null && isset($data->latest[$target]) ? ' (' . $data->latest[$target] . ')' : '');
            if ($fixedInBranch > 0 && $latest !== null) {
                $lines[] = sprintf(
                    '    Fix: upgrade PHP to %s (latest %s release); it fixes %s.',
                    $latest,
                    $env->branch(),
                    $unfixed === 0 ? 'all of them' : sprintf('%d of them', $fixedInBranch)
                );
            }
            if ($unfixed > 0 && $fixedInBranch === 0) {
                $lines[] = sprintf('    Fix: upgrade to PHP %s; none of these are fixed in PHP %s.', $targetText, $env->branch());
            } elseif ($unfixed > 0) {
                $lines[] = sprintf(
                    '    %s %d ha%s no fix listed for PHP %s: upgrade to PHP %s.',
                    $fixedInBranch > 0 ? 'The other' : 'Fix:',
                    $unfixed,
                    $unfixed === 1 ? 's' : 've',
                    $env->branch(),
                    $targetText
                );
            }

            $hidden = 0;
            foreach ($vulnerabilities as $f) {
                if (!$f->isAtLeast(self::COMPACT_LIST_FROM)) {
                    $hidden++;
                    continue;
                }
                $lines[] = sprintf('    - %s [%s] %s', $f->id, $f->severity, $f->title);
            }
            if ($hidden > 0) {
                $lines[] = sprintf('    - … and %d lower-severity one%s', $hidden, $hidden === 1 ? '' : 's');
            }
            $lines[] = '';
        }

        foreach ($report->findings as $finding) {
            if ($finding->check === 'vulnerabilities') {
                continue;
            }
            $tag = self::TAGS[$finding->severity];
            $lines[] = sprintf('<%s>[%s]</%s> %s', $tag, strtoupper($finding->severity), $tag, $finding->title);
            $lines[] = '    Fix: ' . ($finding->fix[0] ?? '');
        }

        $lines[] = '';
        $lines[] = $this->summary($report);
        $lines[] = 'Full details and how-to-fix steps: vendor/bin/php-issues-check';

        return $lines;
    }

    private function summary(Report $report): string
    {
        $parts = [];
        foreach ($report->counts() as $severity => $count) {
            if ($count > 0) {
                $parts[] = $count . ' ' . $severity;
            }
        }

        return sprintf(
            'Found %d issue%s: %s%s',
            count($report->findings),
            count($report->findings) === 1 ? '' : 's',
            implode(', ', $parts),
            $report->ignored > 0 ? sprintf(' (%d ignored)', $report->ignored) : ''
        );
    }
}
