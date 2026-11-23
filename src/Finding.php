<?php

declare(strict_types=1);

namespace PhpIssuesChecker;

/**
 * One problem found by a check, with the steps to fix it.
 */
final class Finding
{
    public const CRITICAL = 'critical';
    public const HIGH = 'high';
    public const MEDIUM = 'medium';
    public const LOW = 'low';
    public const INFO = 'info';

    private const RANKS = [
        self::INFO => 0,
        self::LOW => 1,
        self::MEDIUM => 2,
        self::HIGH => 3,
        self::CRITICAL => 4,
    ];

    /** @var string Which check produced it: version, vulnerabilities, ini */
    public string $check;

    public string $severity;

    /** @var string Stable identifier (CVE/GHSA id, ini key, ...) usable in the ignore list */
    public string $id;

    public string $title;

    public string $details;

    /** @var string[] Ordered steps the user should take */
    public array $fix;

    public ?string $url;

    /** @var string|null For vulnerabilities: the release in your branch that fixes it */
    public ?string $fixedIn = null;

    /**
     * @param string[] $fix
     */
    public function __construct(
        string $check,
        string $severity,
        string $id,
        string $title,
        string $details,
        array $fix,
        ?string $url = null
    ) {
        $this->check = $check;
        $this->severity = self::normalizeSeverity($severity);
        $this->id = $id;
        $this->title = $title;
        $this->details = $details;
        $this->fix = $fix;
        $this->url = $url;
    }

    public static function normalizeSeverity(string $severity): string
    {
        $severity = strtolower(trim($severity));
        if ($severity === 'moderate') {
            $severity = self::MEDIUM;
        }

        return isset(self::RANKS[$severity]) ? $severity : self::MEDIUM;
    }

    public static function isValidSeverity(string $severity): bool
    {
        return isset(self::RANKS[strtolower($severity)]);
    }

    public static function rank(string $severity): int
    {
        return self::RANKS[strtolower($severity)] ?? 0;
    }

    /** @return string[] Severities from most to least severe */
    public static function severities(): array
    {
        return array_reverse(array_keys(self::RANKS));
    }

    public function isAtLeast(string $severity): bool
    {
        return self::rank($this->severity) >= self::rank($severity);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'check' => $this->check,
            'severity' => $this->severity,
            'id' => $this->id,
            'title' => $this->title,
            'details' => $this->details,
            'fix' => $this->fix,
            'url' => $this->url,
            'fixed_in' => $this->fixedIn,
        ];
    }
}
