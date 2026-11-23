<?php

declare(strict_types=1);

namespace PhpIssuesChecker\Report;

/**
 * Generic "how do I upgrade PHP" steps, printed once when an upgrade is needed.
 */
final class UpgradeGuide
{
    /** @return array<string, string> platform => instruction */
    public static function steps(string $currentBranch, ?string $targetBranch): array
    {
        $target = $targetBranch ?? $currentBranch;

        return [
            'Ubuntu / Debian' => sprintf(
                'Same branch: sudo apt update && sudo apt install --only-upgrade "php%s*". New branch: add the ondrej/php PPA (Ubuntu) or packages.sury.org (Debian), then install php%s-fpm and the extensions you use.',
                $currentBranch,
                $target
            ),
            'RHEL / Alma / Rocky' => sprintf('sudo dnf upgrade "php*". For a newer branch use the Remi repository: sudo dnf module switch-to php:remi-%s', $target),
            'Docker' => sprintf('Use the official image tag php:%s-fpm (or -apache/-cli) and rebuild with: docker build --pull .', $target),
            'macOS (Homebrew)' => sprintf('brew update && brew upgrade php (or: brew install php@%s)', $target),
            'Windows' => 'Download the latest build from https://windows.php.net/download/',
            'Shared hosting' => sprintf('Choose PHP %s in your control panel (cPanel "MultiPHP Manager", Plesk "PHP Settings").', $target),
            'After upgrading' => 'Restart PHP-FPM and the web server, run your tests, and confirm the version with php -v and phpinfo() on the web.',
            'Note' => 'Linux distributions often backport security fixes without changing the version number. If your distro does this, check its security tracker (e.g. security-tracker.debian.org, ubuntu.com/security/cves) before treating a CVE as open.',
        ];
    }
}
