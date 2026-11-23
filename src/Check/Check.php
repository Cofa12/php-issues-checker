<?php

declare(strict_types=1);

namespace PhpIssuesChecker\Check;

use PhpIssuesChecker\Data\AdvisoryData;
use PhpIssuesChecker\Environment;
use PhpIssuesChecker\Finding;

interface Check
{
    /** Short name used by --skip (e.g. "version"). */
    public function name(): string;

    /** @return Finding[] */
    public function run(Environment $env, AdvisoryData $data): array;
}
