# PHP Issues Checker

[![CI](https://github.com/Cofa12/php-issues-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/Cofa12/php-issues-checker/actions/workflows/ci.yml)
![PHP](https://img.shields.io/badge/PHP-7.4%20%E2%80%93%208.5-777BB4?logo=php&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)

Checks the **PHP runtime** your project runs on against the issues the **PHP project itself** has officially reported, and tells you how to protect yourself.

It runs automatically after every `composer install` / `composer update`, and you can run it by hand or in CI.

```text
PHP Issues Checker: PHP 8.4.15 (cli), php.ini: /etc/php/8.4/cli/php.ini
Official data: php.net + php/php-src security advisories (live, 2026-11-23, 83 advisories)

[CRITICAL] 46 known security vulnerabilities affect PHP 8.4.15 (7 critical, 10 high, 24 medium, 5 low)
    Fix: upgrade PHP to 8.4.28 (latest 8.4 release); it fixes 45 of them.
    - CVE-2026-129496 [critical] Timezone cache use-after-free can lead to remote code execution
    - CVE-2026-109618 [critical] RCE via OOM corruption
    - … and 29 lower-severity ones

[HIGH] php.ini: display_errors is "1"
    Fix: Set "display_errors = Off" in /etc/php/8.4/cli/php.ini
[MEDIUM] PHP 8.4.15 is not the latest 8.4 release (8.4.28)
    Fix: Update PHP to 8.4.28 (same branch, drop-in upgrade).

Found 58 issues: 7 critical, 11 high, 29 medium, 8 low, 3 info
```

> **What it does not cover:** vulnerabilities in your **Composer dependencies**. Composer already does that: run `composer audit`.

---

## What it checks

### 1. PHP version support (end of life)

Source: [php.net supported versions](https://www.php.net/supported-versions.php) (`releases/states.php` + `releases` JSON API)

| Issue | Severity | What you are told to do |
|---|---|---|
| Your PHP branch is **end-of-life** (no more security fixes) | critical | Upgrade to the newest supported branch, with per-platform steps |
| Your branch is **security-fixes only** | low (medium if support ends within 6 months) | Plan the upgrade before the end date |
| You are not on the **latest patch release** of your branch | medium | Update to the latest patch (drop-in, no compatibility breaks) |
| Your version is newer than anything php.net lists (dev/RC build) | info | Do not run pre-releases in production |

### 2. Known security vulnerabilities (CVEs)

Source: [php/php-src GitHub security advisories](https://github.com/php/php-src/security/advisories), the PHP project's official advisory list

Your exact PHP version is matched against every advisory's affected version range. For each match you get the CVE id, severity (critical / high / medium / low, as given by the PHP security team), the release that fixes it in **your** branch, and a link to the advisory.

It only reports what applies to you:

| Advisory affects | Reported when |
|---|---|
| PHP core / engine | always (if your version is in range) |
| An extension (`ext-soap`, `ext-pgsql`, `ext-phar`, …) | only if that extension is loaded |
| A SAPI (PHP-FPM, PHP-CGI, …) | always, marked *"only if your site runs on PHP-FPM"*, because Composer runs the CLI and cannot see what your web server uses |

### 3. php.ini security settings

Source: the [PHP manual](https://www.php.net/manual/en/ini.list.php) and `php.ini-production`

| Setting | Flagged when | Recommended | Severity | Why |
|---|---|---|---|---|
| `allow_url_include` | On | `Off` | critical | Turns a file-inclusion bug into remote code execution |
| `display_errors` | On | `Off` | high | Leaks paths, SQL and stack traces to visitors |
| `display_startup_errors` | On | `Off` | medium | Leaks startup errors in the output |
| `log_errors` | Off | `On` | medium | You cannot see attacks or failures afterwards |
| `session.use_strict_mode` | 0 | `1` | medium | Prevents session fixation |
| `session.use_only_cookies` | 0 | `1` | medium | Keeps session IDs out of URLs |
| `session.use_trans_sid` | 1 | `0` | medium | Keeps session IDs out of URLs |
| `session.cookie_httponly` | 0 | `1` | medium | Stops XSS from stealing the session cookie |
| `session.cookie_secure` | 0 | `1` | medium | Session cookie only sent over HTTPS |
| `expose_php` | On | `Off` | low | Hides `X-Powered-By: PHP/x.y.z` |
| `session.cookie_samesite` | empty / None | `Lax` | low | Helps against CSRF |
| `zend.assertions` | 1 | `-1` | low | `assert()` is for development only |
| `allow_url_fopen` | On | `Off` (if you can) | info | Reduces the impact of SSRF bugs |
| `disable_functions` | empty | `exec,passthru,shell_exec,system,popen,pcntl_exec` | info | Limits damage after code execution (web `php.ini` only) |
| `open_basedir` | empty | your app directory | info | Limits which files PHP can reach |

Session settings are only checked when the `session` extension is loaded.

### How you are told to fix things

Every issue comes with numbered fix steps and a link to the official source. When PHP needs upgrading, the full report also prints a short upgrade guide for Ubuntu/Debian, RHEL/Alma/Rocky, Docker, macOS (Homebrew), Windows and shared hosting.

---

## Install

```bash
composer require cofa/php-issues-checker
```

Composer will ask whether to trust the plugin. Answer **yes**, or add this to your `composer.json`:

```json
{
    "config": {
        "allow-plugins": {
            "cofa/php-issues-checker": true
        }
    }
}
```

Install it with `require` (not `--dev`) if you want it to also run when you deploy with `composer install --no-dev`.

Requirements: PHP 7.4 or newer, Composer 2.

## Usage

### Automatically, on `composer install` / `update`

After each install or update you get a compact report (CVEs grouped, one line per issue). By default it **only warns** and never breaks your install.

Configure it in your project's `composer.json`:

```json
{
    "extra": {
        "php-issues-checker": {
            "fail-on": "critical",
            "ignore": ["CVE-2026-129289", "disable_functions", "open_basedir"],
            "skip": ["ini"],
            "offline": false,
            "verbose": false,
            "enabled": true
        }
    }
}
```

| Option | Default | Meaning |
|---|---|---|
| `fail-on` | `none` | Make `composer install` fail when an issue of this severity or higher is found: `none`, `info`, `low`, `medium`, `high`, `critical` |
| `ignore` | `[]` | Issue ids to hide: CVE or GHSA ids, php.ini keys, or `php-branch-eol`, `php-branch-security-only`, `php-patch-outdated`, `php-branch-unknown` |
| `skip` | `[]` | Checks to skip: `version`, `vulnerabilities`, `ini` |
| `offline` | `false` | Never download; use the data snapshot bundled with the package |
| `php-version` | – | Check this version instead of the running PHP (e.g. your production version) |
| `verbose` | `false` | Print the full report instead of the compact one |
| `enabled` | `true` | Turn the automatic check off |

To skip it once: `PHP_ISSUES_CHECKER_DISABLE=1 composer install`.

### By hand / in CI

```bash
vendor/bin/php-issues-check
```

```text
--format=text|json        Output format (default: text)
--fail-on=SEVERITY        Exit code 1 if an issue of this severity or higher is found
--skip=CHECKS             version,vulnerabilities,ini
--ignore=IDS              CVE-…, GHSA-…, ini keys
--php-version=X.Y.Z       Check another version (ini checks are skipped, extensions unknown)
--compact                 Grouped, one line per issue
--offline                 Use the bundled snapshot only
--color / --no-color
```

Exit codes: `0` ok, `1` issues at or above `--fail-on`, `2` error.

GitHub Actions example:

```yaml
- run: composer install --no-interaction
- run: vendor/bin/php-issues-check --fail-on=high
# Also check the PHP version you run in production:
- run: vendor/bin/php-issues-check --php-version=8.3.12 --fail-on=critical
```

### Checking the web server PHP

Composer and CI run the **command-line** PHP. Your website may run a **different PHP version and php.ini** (PHP-FPM, Apache mod_php). To check that one, run the checker from inside your app, for example on an admin-only page:

```php
use PhpIssuesChecker\Checker;
use PhpIssuesChecker\Report\TextReporter;

$report = (new Checker())->run();

echo '<pre>' . htmlspecialchars(strip_tags(implode("\n", (new TextReporter())->render($report)))) . '</pre>';
```

Never expose this page publicly: it tells attackers exactly what is vulnerable.

## Where the data comes from

| Data | Official source |
|---|---|
| Supported branches and end-of-life dates | `https://www.php.net/releases/states.php` |
| Latest release of each branch | `https://www.php.net/releases/index.php?json` |
| Security advisories (CVEs) | `https://api.github.com/repos/php/php-src/security-advisories` |

- Data is downloaded live and cached for 24 hours (in Composer's cache directory, or the system temp directory).
- If downloading fails (no internet, firewall, GitHub rate limit), it falls back to the cache, then to the snapshot bundled in `data/snapshot.json`, and tells you how old that data is.
- Set `GITHUB_TOKEN` to avoid GitHub's anonymous rate limit (60 requests per hour) on busy CI runners.
- Nothing about your project is sent anywhere: the checker only downloads public data.

## Limitations

- **Distribution backports.** Debian, Ubuntu, RHEL and others often patch security issues without changing the PHP version number. On those systems a CVE may be reported even though your distro has fixed it. Check your distro's security tracker and add the id to `ignore`.
- **CLI vs. web.** See [Checking the web server PHP](#checking-the-web-server-php).
- **Advisory quality.** Version ranges come straight from the php-src advisories. When an advisory lists no fix for your branch, the checker recommends a newer branch.

## Development

```bash
composer install
composer test            # PHPUnit
composer lint            # code style check (PHP-CS-Fixer, PSR-12); composer lint:fix to fix
composer analyse         # static analysis (PHPStan)
composer check           # all three
composer update-data     # refresh data/snapshot.json before a release
```

### CI/CD

GitHub Actions runs on every push to `main` and every pull request:

| Job | What it does |
|---|---|
| Lint & static analysis | `composer validate`, PHP-CS-Fixer (PSR-12), PHPStan |
| Tests (PHP 7.4 → 8.5) | `php -l` syntax check, PHPUnit, and a smoke test of the CLI on every supported PHP version |

Releasing: bump `VERSION` in `src/Cli/Application.php`, commit, then push a tag (`git tag v0.2.0 && git push origin v0.2.0`). The release workflow runs the full CI, checks the tag matches the version, and publishes a GitHub release with generated notes. Packagist picks up the new tag automatically.

## License

MIT. See [LICENSE](LICENSE).
