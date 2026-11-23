<?php

declare(strict_types=1);

namespace PhpIssuesChecker;

/**
 * Settings shared by the CLI and the Composer plugin.
 */
final class Options
{
    /** @var string Severity that makes the run fail, or "none" */
    public string $failOn = 'none';

    public bool $offline = false;

    /** @var string[] Checks to skip: version, vulnerabilities, ini */
    public array $skip = [];

    /** @var string[] Finding ids to ignore (CVE-…, GHSA-…, ini keys, php-branch-eol, …) */
    public array $ignore = [];

    /** @var string|null Check this PHP version instead of the running one */
    public ?string $phpVersion = null;

    /**
     * Builds options from the "extra.php-issues-checker" section of composer.json.
     *
     * @param array<string, mixed> $config
     */
    public static function fromArray(array $config): self
    {
        $options = new self();
        if (isset($config['fail-on'])) {
            $options->setFailOn((string) $config['fail-on']);
        }
        $options->offline = (bool) ($config['offline'] ?? false);
        $options->skip = self::toList($config['skip'] ?? []);
        $options->ignore = self::toList($config['ignore'] ?? []);
        if (isset($config['php-version']) && $config['php-version'] !== '') {
            $options->phpVersion = (string) $config['php-version'];
        }

        return $options;
    }

    public function setFailOn(string $severity): void
    {
        $severity = strtolower(trim($severity));
        if ($severity !== 'none' && !Finding::isValidSeverity($severity)) {
            throw new \InvalidArgumentException(sprintf(
                'Invalid fail-on value "%s". Use one of: none, %s.',
                $severity,
                implode(', ', Finding::severities())
            ));
        }
        $this->failOn = $severity;
    }

    /**
     * @param mixed $value
     *
     * @return string[]
     */
    public static function toList($value): array
    {
        if (is_string($value)) {
            $value = explode(',', $value);
        }
        if (!is_array($value)) {
            return [];
        }

        return array_values(array_filter(array_map(static function ($item): string {
            return trim((string) $item);
        }, $value), static function (string $item): bool {
            return $item !== '';
        }));
    }
}
