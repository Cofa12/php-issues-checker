<?php

declare(strict_types=1);

namespace PhpIssuesChecker\Tests;

use PhpIssuesChecker\VersionRange;
use PHPUnit\Framework\TestCase;

final class VersionRangeTest extends TestCase
{
    /** @return iterable<string, array{string, string, bool}> */
    public static function cases(): iterable
    {
        yield 'and range inside' => ['8.3.5', '>= 8.3.0, < 8.3.37', true];
        yield 'and range upper bound excluded' => ['8.3.37', '>= 8.3.0, < 8.3.37', false];
        yield 'and range below' => ['8.2.9', '>= 8.3.0, < 8.3.37', false];
        yield 'less than without space' => ['8.4.25', '<8.4.26', true];
        yield 'less or equal' => ['8.1.31', '<=8.1.31', true];
        yield 'exact' => ['8.4.1', '8.4.1', true];
        yield 'exact other' => ['8.4.2', '8.4.1', false];
        yield 'hyphen list second' => ['8.2.10', '8.1.0 - 8.1.31, 8.2.0 - 8.2.27', true];
        yield 'hyphen list none' => ['8.3.0', '8.1.0 - 8.1.31, 8.2.0 - 8.2.27', false];
        yield 'or alternatives' => ['7.4.3', '>= 8.0.0, < 8.0.5 || < 7.4.10', true];
        yield 'garbage is not a match' => ['8.4.1', 'all versions', false];
        yield 'empty' => ['8.4.1', '', false];
    }

    /** @dataProvider cases */
    public function testMatches(string $version, string $range, bool $expected): void
    {
        self::assertSame($expected, VersionRange::matches($version, $range));
    }
}
