<?php

declare(strict_types=1);

/*
 * Refreshes data/snapshot.json (the offline fallback) from php.net and the
 * php/php-src GitHub security advisories. Run before each release:
 *
 *     composer update-data
 *
 * Set GITHUB_TOKEN to avoid GitHub's anonymous rate limit.
 */

require __DIR__ . '/../vendor/autoload.php';

use PhpIssuesChecker\Data\DataProvider;

$data = (new DataProvider())->fetchLive();
$file = __DIR__ . '/../data/snapshot.json';

if (!is_dir(dirname($file))) {
    mkdir(dirname($file), 0777, true);
}

file_put_contents(
    $file,
    json_encode($data->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL
);

printf(
    "Wrote %s: %d branches, %d advisories (generated %s)\n",
    realpath($file),
    count($data->branches),
    count($data->advisories),
    $data->generatedAt
);
