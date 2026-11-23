<?php

declare(strict_types=1);

namespace PhpIssuesChecker\Check;

use PhpIssuesChecker\Data\AdvisoryData;
use PhpIssuesChecker\Environment;
use PhpIssuesChecker\Finding;

/**
 * Compares php.ini against the production recommendations from the
 * PHP manual and php.ini-production.
 */
final class IniSettingsCheck implements Check
{
    private const MANUAL = 'https://www.php.net/manual/en/';

    public function name(): string
    {
        return 'ini';
    }

    /**
     * Each rule: setting, severity, when it is a problem, the recommended
     * line for php.ini, why it matters, and which extension it needs.
     *
     * @return list<array{key: string, severity: string, bad: callable(string): bool, recommended: string, why: string, url: string, requires?: string}>
     */
    public static function rules(): array
    {
        $on = static function (string $v): bool {
            return self::isOn($v);
        };
        $off = static function (string $v): bool {
            return !self::isOn($v);
        };

        return [
            [
                'key' => 'allow_url_include',
                'severity' => Finding::CRITICAL,
                'bad' => $on,
                'recommended' => 'allow_url_include = Off',
                'why' => 'Lets include/require load code from URLs, which turns any file-inclusion bug into remote code execution.',
                'url' => self::MANUAL . 'filesystem.configuration.php#ini.allow-url-include',
            ],
            [
                'key' => 'display_errors',
                'severity' => Finding::HIGH,
                'bad' => static function (string $v): bool {
                    return strtolower($v) !== 'stderr' && self::isOn($v);
                },
                'recommended' => 'display_errors = Off',
                'why' => 'Shows error messages, file paths, SQL and stack traces to visitors, which helps attackers map your application.',
                'url' => self::MANUAL . 'errorfunc.configuration.php#ini.display-errors',
            ],
            [
                'key' => 'display_startup_errors',
                'severity' => Finding::MEDIUM,
                'bad' => $on,
                'recommended' => 'display_startup_errors = Off',
                'why' => 'Shows PHP startup errors (paths, extension problems) in the output.',
                'url' => self::MANUAL . 'errorfunc.configuration.php#ini.display-startup-errors',
            ],
            [
                'key' => 'log_errors',
                'severity' => Finding::MEDIUM,
                'bad' => $off,
                'recommended' => 'log_errors = On',
                'why' => 'Without error logs you cannot see attacks or failures after the fact.',
                'url' => self::MANUAL . 'errorfunc.configuration.php#ini.log-errors',
            ],
            [
                'key' => 'expose_php',
                'severity' => Finding::LOW,
                'bad' => $on,
                'recommended' => 'expose_php = Off',
                'why' => 'Adds an "X-Powered-By: PHP/x.y.z" header, telling attackers exactly which vulnerabilities to try.',
                'url' => self::MANUAL . 'ini.core.php#ini.expose-php',
            ],
            [
                'key' => 'session.use_strict_mode',
                'severity' => Finding::MEDIUM,
                'bad' => $off,
                'recommended' => 'session.use_strict_mode = 1',
                'why' => 'Without strict mode PHP accepts session IDs it never created, enabling session fixation.',
                'url' => self::MANUAL . 'session.configuration.php#ini.session.use-strict-mode',
                'requires' => 'session',
            ],
            [
                'key' => 'session.use_only_cookies',
                'severity' => Finding::MEDIUM,
                'bad' => $off,
                'recommended' => 'session.use_only_cookies = 1',
                'why' => 'Allows session IDs in URLs, where they leak through logs, Referer headers and shared links.',
                'url' => self::MANUAL . 'session.configuration.php#ini.session.use-only-cookies',
                'requires' => 'session',
            ],
            [
                'key' => 'session.use_trans_sid',
                'severity' => Finding::MEDIUM,
                'bad' => $on,
                'recommended' => 'session.use_trans_sid = 0',
                'why' => 'Rewrites links to carry the session ID in the URL, which leaks it.',
                'url' => self::MANUAL . 'session.configuration.php#ini.session.use-trans-sid',
                'requires' => 'session',
            ],
            [
                'key' => 'session.cookie_httponly',
                'severity' => Finding::MEDIUM,
                'bad' => $off,
                'recommended' => 'session.cookie_httponly = 1',
                'why' => 'Lets JavaScript read the session cookie, so any XSS bug can steal user sessions.',
                'url' => self::MANUAL . 'session.configuration.php#ini.session.cookie-httponly',
                'requires' => 'session',
            ],
            [
                'key' => 'session.cookie_secure',
                'severity' => Finding::MEDIUM,
                'bad' => $off,
                'recommended' => 'session.cookie_secure = 1',
                'why' => 'Session cookies may be sent over plain HTTP and intercepted. Set this when your site uses HTTPS (it should).',
                'url' => self::MANUAL . 'session.configuration.php#ini.session.cookie-secure',
                'requires' => 'session',
            ],
            [
                'key' => 'session.cookie_samesite',
                'severity' => Finding::LOW,
                'bad' => static function (string $v): bool {
                    return !in_array(strtolower(trim($v)), ['lax', 'strict'], true);
                },
                'recommended' => 'session.cookie_samesite = Lax',
                'why' => 'Without SameSite the session cookie is sent on cross-site requests, which helps CSRF attacks.',
                'url' => self::MANUAL . 'session.configuration.php#ini.session.cookie-samesite',
                'requires' => 'session',
            ],
            [
                'key' => 'zend.assertions',
                'severity' => Finding::LOW,
                'bad' => static function (string $v): bool {
                    return (int) $v === 1;
                },
                'recommended' => 'zend.assertions = -1',
                'why' => 'assert() code runs in production; it is meant for development only and costs performance.',
                'url' => self::MANUAL . 'ini.core.php#ini.zend.assertions',
            ],
            [
                'key' => 'allow_url_fopen',
                'severity' => Finding::INFO,
                'bad' => $on,
                'recommended' => 'allow_url_fopen = Off',
                'why' => 'File functions can open remote URLs, which widens the impact of SSRF bugs. Keep it On only if your code (or a library) needs it; ext-curl does not.',
                'url' => self::MANUAL . 'filesystem.configuration.php#ini.allow-url-fopen',
            ],
            [
                'key' => 'disable_functions',
                'severity' => Finding::INFO,
                'bad' => static function (string $v): bool {
                    return trim($v) === '';
                },
                'recommended' => 'disable_functions = exec,passthru,shell_exec,system,popen,pcntl_exec',
                'why' => 'If an attacker gets code execution, shell functions let them take over the server. Disable the ones your web app does not use (in the web php.ini only: Composer and many CLI tools need proc_open).',
                'url' => self::MANUAL . 'ini.core.php#ini.disable-functions',
            ],
            [
                'key' => 'open_basedir',
                'severity' => Finding::INFO,
                'bad' => static function (string $v): bool {
                    return trim($v) === '';
                },
                'recommended' => 'open_basedir = /var/www/your-app:/tmp',
                'why' => 'Limits which directories PHP can read and write, so a path-traversal bug cannot reach /etc or other sites. Set it in the php.ini your web server uses (PHP-FPM / Apache), not the command-line one: in the CLI it breaks Composer and other tools.',
                'url' => self::MANUAL . 'ini.core.php#ini.open-basedir',
            ],
        ];
    }

    public function run(Environment $env, AdvisoryData $data): array
    {
        if (!$env->knowsIni()) {
            return [];
        }

        $iniFile = $env->iniFile() ?? 'your php.ini (none is loaded right now: run "php --ini")';
        $findings = [];

        foreach (self::rules() as $rule) {
            if (isset($rule['requires']) && !$env->hasExtension($rule['requires'])) {
                continue;
            }
            $value = $env->ini($rule['key']);
            if ($value === null || !($rule['bad'])($value)) {
                continue;
            }

            $findings[] = new Finding(
                'ini',
                $rule['severity'],
                $rule['key'],
                sprintf('php.ini: %s is "%s"', $rule['key'], $value === '' ? '(empty)' : $value),
                $rule['why'],
                [
                    sprintf('Set "%s" in %s', $rule['recommended'], $iniFile),
                    'Restart PHP-FPM / your web server so the change takes effect.',
                ],
                $rule['url']
            );
        }

        return $findings;
    }

    public static function isOn(string $value): bool
    {
        return in_array(strtolower(trim($value)), ['1', 'on', 'yes', 'true', 'stdout', 'stderr'], true);
    }
}
