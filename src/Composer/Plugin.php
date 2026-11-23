<?php

declare(strict_types=1);

namespace PhpIssuesChecker\Composer;

use Composer\Composer;
use Composer\EventDispatcher\EventSubscriberInterface;
use Composer\IO\IOInterface;
use Composer\Plugin\PluginInterface;
use Composer\Script\Event;
use Composer\Script\ScriptEvents;
use PhpIssuesChecker\Checker;
use PhpIssuesChecker\Data\DataProvider;
use PhpIssuesChecker\Options;
use PhpIssuesChecker\Report\TextReporter;

/**
 * Runs the checks after every "composer install" and "composer update".
 *
 * Configure in the project's composer.json:
 *
 *     "extra": { "php-issues-checker": { "fail-on": "critical", "ignore": ["CVE-2024-1234"] } }
 *
 * Disable for one run with PHP_ISSUES_CHECKER_DISABLE=1.
 */
final class Plugin implements PluginInterface, EventSubscriberInterface
{
    private Composer $composer;

    private IOInterface $io;

    private bool $ran = false;

    public function activate(Composer $composer, IOInterface $io): void
    {
        $this->composer = $composer;
        $this->io = $io;
    }

    public function deactivate(Composer $composer, IOInterface $io): void
    {
    }

    public function uninstall(Composer $composer, IOInterface $io): void
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            ScriptEvents::POST_INSTALL_CMD => 'onPostInstall',
            ScriptEvents::POST_UPDATE_CMD => 'onPostInstall',
        ];
    }

    public function onPostInstall(Event $event): void
    {
        if ($this->ran || filter_var(getenv('PHP_ISSUES_CHECKER_DISABLE'), FILTER_VALIDATE_BOOLEAN)) {
            return;
        }
        $this->ran = true;

        $extra = $this->composer->getPackage()->getExtra();
        $config = isset($extra['php-issues-checker']) && is_array($extra['php-issues-checker']) ? $extra['php-issues-checker'] : [];
        if (($config['enabled'] ?? true) === false) {
            return;
        }

        try {
            $options = Options::fromArray($config);
            $cacheDir = (string) $this->composer->getConfig()->get('cache-dir');
            $checker = new Checker(new DataProvider($options->offline, is_dir($cacheDir) ? $cacheDir : null));
            $report = $checker->run($options);
        } catch (\Throwable $e) {
            $this->io->writeError('<warning>PHP Issues Checker could not run: ' . $e->getMessage() . '</warning>');

            return;
        }

        $this->io->writeError('');
        foreach ((new TextReporter(($config['verbose'] ?? false) !== true))->render($report) as $line) {
            $this->io->writeError($line);
        }

        if ($report->hasAtLeast($options->failOn)) {
            $message = sprintf(
                'PHP Issues Checker found issues of severity "%s" or higher. Fix them, add their ids to "extra.php-issues-checker.ignore", or change "fail-on" in composer.json.',
                $options->failOn
            );
            $this->io->writeError('');
            $this->io->writeError('<error>' . $message . '</error>');

            // Composer exits with this code without printing a stack/usage dump.
            $class = 'Composer\\EventDispatcher\\ScriptExecutionException';
            if (class_exists($class)) {
                throw new $class($message, 1);
            }
            throw new \RuntimeException($message, 1);
        }
    }
}
