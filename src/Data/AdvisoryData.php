<?php

declare(strict_types=1);

namespace PhpIssuesChecker\Data;

/**
 * The official data the checks run against.
 */
final class AdvisoryData
{
    public const SOURCE_LIVE = 'live';
    public const SOURCE_CACHE = 'cache';
    public const SOURCE_BUNDLED = 'bundled snapshot';

    /** @var array<string, array{state: string, initial_release: ?string, active_support_end: ?string, security_support_end: ?string}> branch => support info */
    public array $branches;

    /** @var array<string, string> branch => latest released version */
    public array $latest;

    /** @var list<array{id: string, cve: ?string, severity: string, summary: string, url: string, published: ?string, affected: list<array{component: string, range: string, patched: string}>}> */
    public array $advisories;

    public string $generatedAt;

    public string $source;

    /** @var string|null Why live data could not be used, if it could not */
    public ?string $warning = null;

    /**
     * @param array<string, mixed> $branches
     * @param array<string, string> $latest
     * @param list<array<string, mixed>> $advisories
     */
    public function __construct(array $branches, array $latest, array $advisories, string $generatedAt, string $source)
    {
        $this->branches = $branches;
        $this->latest = $latest;
        $this->advisories = $advisories;
        $this->generatedAt = $generatedAt;
        $this->source = $source;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data, string $source): self
    {
        foreach (['branches', 'latest', 'advisories', 'generated_at'] as $key) {
            if (!isset($data[$key])) {
                throw new \UnexpectedValueException(sprintf('Advisory data is missing "%s".', $key));
            }
        }

        return new self($data['branches'], $data['latest'], $data['advisories'], (string) $data['generated_at'], $source);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'generated_at' => $this->generatedAt,
            'sources' => [
                'https://www.php.net/releases/states.php',
                'https://www.php.net/releases/index.php?json',
                'https://github.com/php/php-src/security/advisories',
            ],
            'branches' => $this->branches,
            'latest' => $this->latest,
            'advisories' => $this->advisories,
        ];
    }

    /**
     * Newest branch that is still supported ("stable" or "security").
     */
    public function newestSupportedBranch(): ?string
    {
        $best = null;
        foreach ($this->branches as $branch => $info) {
            if (in_array($info['state'] ?? '', ['stable', 'security'], true)
                && ($best === null || version_compare((string) $branch, $best, '>'))) {
                $best = (string) $branch;
            }
        }

        return $best;
    }
}
