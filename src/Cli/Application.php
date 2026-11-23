<?php

declare(strict_types=1);

namespace PhpIssuesChecker\Cli;

use PhpIssuesChecker\Checker;
use PhpIssuesChecker\Data\DataProvider;
use PhpIssuesChecker\Finding;
use PhpIssuesChecker\Options;
use PhpIssuesChecker\Report\JsonReporter;
use PhpIssuesChecker\Report\TextReporter;

final class Application
{
    public const VERSION = '0.2.0';

    public const EXIT_OK = 0;
    public const EXIT_ISSUES = 1;
    public const EXIT_ERROR = 2;

    private const ANSI = [
        'error' => "\033[1;31m",
        'comment' => "\033[33m",
        'info' => "\033[32m",
        'warning' => "\033[33m",
    ];

    /** @var resource */
    private $stdout;

    /** @var resource */
    private $stderr;

    /**
     * @param resource|null $stdout
     * @param resource|null $stderr
     */
    public function __construct($stdout = null, $stderr = null)
    {
        $this->stdout = $stdout ?? STDOUT;
        $this->stderr = $stderr ?? STDERR;
    }

    /** @param string[] $argv */
    public function run(array $argv): int
    {
        try {
            $parsed = $this->parse(array_slice($argv, 1));
        } catch (\InvalidArgumentException $e) {
            fwrite($this->stderr, 'Error: ' . $e->getMessage() . PHP_EOL . 'Run with --help for usage.' . PHP_EOL);

            return self::EXIT_ERROR;
        }

        if ($parsed['help']) {
            fwrite($this->stdout, $this->help());

            return self::EXIT_OK;
        }
        if ($parsed['version']) {
            fwrite($this->stdout, 'php-issues-checker ' . self::VERSION . PHP_EOL);

            return self::EXIT_OK;
        }

        /** @var Options $options */
        $options = $parsed['options'];

        try {
            $report = (new Checker(new DataProvider($options->offline)))->run($options);
        } catch (\Throwable $e) {
            fwrite($this->stderr, 'Error: ' . $e->getMessage() . PHP_EOL);

            return self::EXIT_ERROR;
        }

        if ($parsed['format'] === 'json') {
            fwrite($this->stdout, (new JsonReporter())->render($report) . PHP_EOL);
        } else {
            $color = $parsed['color'] ?? $this->supportsColor();
            foreach ((new TextReporter($parsed['compact']))->render($report) as $line) {
                fwrite($this->stdout, $this->format($line, $color) . PHP_EOL);
            }
        }

        return $report->hasAtLeast($options->failOn) ? self::EXIT_ISSUES : self::EXIT_OK;
    }

    /**
     * @param string[] $args
     *
     * @return array{help: bool, version: bool, format: string, compact: bool, color: ?bool, options: Options}
     */
    private function parse(array $args): array
    {
        $options = new Options();
        $result = ['help' => false, 'version' => false, 'format' => 'text', 'compact' => false, 'color' => null, 'options' => $options];

        foreach ($args as $arg) {
            [$name, $value] = array_pad(explode('=', $arg, 2), 2, null);
            switch ($name) {
                case '-h':
                case '--help':
                    $result['help'] = true;
                    break;
                case '-V':
                case '--version':
                    $result['version'] = true;
                    break;
                case '--format':
                    if (!in_array($value, ['text', 'json'], true)) {
                        throw new \InvalidArgumentException('--format must be "text" or "json".');
                    }
                    $result['format'] = $value;
                    break;
                case '--fail-on':
                    $options->setFailOn((string) $value);
                    break;
                case '--compact':
                    $result['compact'] = true;
                    break;
                case '--offline':
                    $options->offline = true;
                    break;
                case '--skip':
                    $options->skip = Options::toList((string) $value);
                    $unknown = array_diff($options->skip, Checker::checkNames());
                    if ($unknown !== []) {
                        throw new \InvalidArgumentException(sprintf('Unknown check "%s". Available: %s.', implode('", "', $unknown), implode(', ', Checker::checkNames())));
                    }
                    break;
                case '--ignore':
                    $options->ignore = Options::toList((string) $value);
                    break;
                case '--php-version':
                    if ($value === null || $value === '') {
                        throw new \InvalidArgumentException('--php-version needs a value, e.g. --php-version=8.2.10');
                    }
                    $options->phpVersion = $value;
                    break;
                case '--no-color':
                    $result['color'] = false;
                    break;
                case '--color':
                    $result['color'] = true;
                    break;
                default:
                    throw new \InvalidArgumentException(sprintf('Unknown option "%s".', $arg));
            }
        }

        return $result;
    }

    private function format(string $line, bool $color): string
    {
        return (string) preg_replace_callback('#<(/?)(error|comment|info|warning)>#', static function (array $m) use ($color): string {
            if (!$color) {
                return '';
            }

            return $m[1] === '/' ? "\033[0m" : self::ANSI[$m[2]];
        }, $line);
    }

    private function supportsColor(): bool
    {
        if (getenv('NO_COLOR') !== false) {
            return false;
        }

        return function_exists('stream_isatty') && @stream_isatty($this->stdout);
    }

    private function help(): string
    {
        $severities = implode('|', Finding::severities());

        return <<<HELP
php-issues-checker {$this->version()}
Checks this PHP installation against officially reported PHP issues
(php.net supported versions + php/php-src security advisories).

Usage:
  vendor/bin/php-issues-check [options]

Options:
  --format=text|json        Output format (default: text)
  --fail-on=none|{$severities}
                            Exit with code 1 when an issue of this severity
                            or higher is found (default: none)
  --skip=CHECKS             Comma-separated checks to skip: version,vulnerabilities,ini
  --ignore=IDS              Comma-separated ids to ignore (CVE-…, GHSA-…, ini keys)
  --php-version=X.Y.Z       Check another PHP version (e.g. your production one);
                            ini checks are skipped and extensions are unknown
  --compact                 Group CVEs and print one line per issue
  --offline                 Do not download data; use the bundled snapshot
  --color / --no-color      Force or disable colours
  -h, --help                Show this help
  -V, --version             Show the version

Exit codes: 0 = ok, 1 = issues at or above --fail-on, 2 = error

HELP;
    }

    private function version(): string
    {
        return self::VERSION;
    }
}
