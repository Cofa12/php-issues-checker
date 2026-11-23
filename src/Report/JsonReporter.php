<?php

declare(strict_types=1);

namespace PhpIssuesChecker\Report;

use PhpIssuesChecker\Finding;
use PhpIssuesChecker\Report;

final class JsonReporter
{
    public function render(Report $report): string
    {
        $env = $report->environment;
        $data = $report->data;

        $payload = [
            'php' => [
                'version' => $env->phpVersion(),
                'branch' => $env->branch(),
                'sapi' => $env->sapi(),
                'ini_file' => $env->iniFile(),
            ],
            'data' => [
                'source' => $data->source,
                'generated_at' => $data->generatedAt,
                'advisories' => count($data->advisories),
                'warning' => $data->warning,
            ],
            'summary' => $report->counts() + ['total' => count($report->findings), 'ignored' => $report->ignored],
            'findings' => array_map(static function (Finding $finding): array {
                return $finding->toArray();
            }, $report->findings),
        ];

        return (string) json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
