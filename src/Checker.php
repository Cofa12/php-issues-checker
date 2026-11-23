<?php

declare(strict_types=1);

namespace PhpIssuesChecker;

use PhpIssuesChecker\Check\Check;
use PhpIssuesChecker\Check\IniSettingsCheck;
use PhpIssuesChecker\Check\KnownVulnerabilitiesCheck;
use PhpIssuesChecker\Check\VersionSupportCheck;
use PhpIssuesChecker\Data\DataProvider;

/**
 * Entry point. Usage from your own code (e.g. an admin page, so the web
 * server's PHP is checked rather than the CLI one):
 *
 *     $report = (new \PhpIssuesChecker\Checker())->run();
 *     foreach ($report->findings as $finding) { ... }
 */
final class Checker
{
    private DataProvider $provider;

    /** @var Check[] */
    private array $checks;

    /** @param Check[]|null $checks */
    public function __construct(?DataProvider $provider = null, ?array $checks = null)
    {
        $this->provider = $provider ?? new DataProvider();
        $this->checks = $checks ?? self::defaultChecks();
    }

    /** @return Check[] */
    public static function defaultChecks(): array
    {
        return [
            new VersionSupportCheck(),
            new KnownVulnerabilitiesCheck(),
            new IniSettingsCheck(),
        ];
    }

    /** @return string[] */
    public static function checkNames(): array
    {
        return array_map(static function (Check $check): string {
            return $check->name();
        }, self::defaultChecks());
    }

    public function run(?Options $options = null, ?Environment $environment = null): Report
    {
        $options = $options ?? new Options();
        $environment = $environment
            ?? ($options->phpVersion !== null ? Environment::forVersion($options->phpVersion) : Environment::current());

        $data = $this->provider->load();
        $ignore = array_map('strtolower', $options->ignore);
        $skip = array_map('strtolower', $options->skip);

        $findings = [];
        $ignored = 0;
        foreach ($this->checks as $check) {
            if (in_array(strtolower($check->name()), $skip, true)) {
                continue;
            }
            foreach ($check->run($environment, $data) as $finding) {
                if (in_array(strtolower($finding->id), $ignore, true)) {
                    $ignored++;
                    continue;
                }
                $findings[] = $finding;
            }
        }

        return new Report($environment, $data, $findings, $ignored);
    }
}
