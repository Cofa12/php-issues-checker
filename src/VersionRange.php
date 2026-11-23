<?php

declare(strict_types=1);

namespace PhpIssuesChecker;

/**
 * Matches a PHP version against the range strings used in php/php-src
 * GitHub security advisories. Supported forms:
 *
 *   ">= 8.3.0, < 8.3.37"   (all constraints must match)
 *   "< 8.2.36", "<=8.1.31", "8.4.1"
 *   "8.1.0 - 8.1.31, 8.2.0 - 8.2.27"   (any hyphen range may match)
 *   "a || b"   (any alternative may match)
 */
final class VersionRange
{
    public static function matches(string $version, string $range): bool
    {
        $range = trim($range);
        if ($range === '') {
            return false;
        }

        foreach (preg_split('/\s*\|\|\s*/', $range) ?: [] as $alternative) {
            if (strpos($alternative, ' - ') !== false) {
                if (self::matchesHyphenList($version, $alternative)) {
                    return true;
                }
                continue;
            }

            if (self::matchesAll($version, $alternative)) {
                return true;
            }
        }

        return false;
    }

    private static function matchesHyphenList(string $version, string $list): bool
    {
        foreach (explode(',', $list) as $part) {
            $bounds = array_map('trim', explode(' - ', $part, 2));
            if (count($bounds) !== 2 || $bounds[0] === '' || $bounds[1] === '') {
                continue;
            }
            if (version_compare($version, $bounds[0], '>=') && version_compare($version, $bounds[1], '<=')) {
                return true;
            }
        }

        return false;
    }

    private static function matchesAll(string $version, string $constraints): bool
    {
        $checked = 0;
        foreach (explode(',', $constraints) as $constraint) {
            $constraint = trim($constraint);
            if ($constraint === '') {
                continue;
            }
            if (!preg_match('/^(>=|<=|>|<|==|=)?\s*v?(\d[\w.\-]*)$/', $constraint, $m)) {
                return false; // unknown syntax: do not guess
            }
            $operator = $m[1] === '' || $m[1] === '=' ? '==' : $m[1];
            if (!version_compare($version, $m[2], $operator)) {
                return false;
            }
            $checked++;
        }

        return $checked > 0;
    }
}
