<?php

declare(strict_types=1);

namespace PhpIssuesChecker;

/**
 * The PHP runtime being checked: either the one running this code,
 * or a version passed by hand (e.g. the production version from CI).
 */
final class Environment
{
    private string $phpVersion;

    private string $sapi;

    /** @var string[]|null Lower-cased loaded extensions; null when unknown */
    private ?array $extensions;

    /** @var array<string, string|false>|null ini values; null when unknown */
    private ?array $ini;

    private ?string $iniFile;

    /**
     * @param string[]|null                    $extensions
     * @param array<string, string|false>|null $ini
     */
    public function __construct(
        string $phpVersion,
        string $sapi,
        ?array $extensions,
        ?array $ini,
        ?string $iniFile = null
    ) {
        $this->phpVersion = self::normalizeVersion($phpVersion);
        $this->sapi = $sapi;
        $this->extensions = $extensions === null ? null : array_map('strtolower', $extensions);
        $this->ini = $ini;
        $this->iniFile = $iniFile;
    }

    public static function current(): self
    {
        $ini = [];
        $all = ini_get_all(null, false);
        if (is_array($all)) {
            foreach ($all as $key => $value) {
                $ini[(string) $key] = $value === null ? '' : (string) $value;
            }
        }

        return new self(
            sprintf('%d.%d.%d', PHP_MAJOR_VERSION, PHP_MINOR_VERSION, PHP_RELEASE_VERSION),
            PHP_SAPI,
            get_loaded_extensions(),
            $ini,
            self::loadedIniFile()
        );
    }

    /**
     * Composer restarts PHP with a temporary php.ini (to disable Xdebug);
     * report the user's real php.ini in that case.
     */
    private static function loadedIniFile(): ?string
    {
        $original = getenv('COMPOSER_ORIGINAL_INIS');
        if (is_string($original) && $original !== '') {
            $first = explode(PATH_SEPARATOR, $original)[0];

            return $first !== '' ? $first : null;
        }

        $loaded = php_ini_loaded_file();

        return $loaded === false ? null : $loaded;
    }

    /**
     * A version checked "by hand": extensions and ini settings are unknown.
     */
    public static function forVersion(string $phpVersion): self
    {
        return new self($phpVersion, 'unknown', null, null);
    }

    /**
     * Turns "8.4.15-1ubuntu2" or "8.4" into "8.4.15" / "8.4.0".
     */
    public static function normalizeVersion(string $version): string
    {
        if (!preg_match('/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/', trim($version), $m)) {
            throw new \InvalidArgumentException(sprintf('"%s" is not a valid PHP version.', $version));
        }

        return sprintf('%d.%d.%d', $m[1], $m[2] ?? 0, $m[3] ?? 0);
    }

    public function phpVersion(): string
    {
        return $this->phpVersion;
    }

    /** "8.4" */
    public function branch(): string
    {
        $parts = explode('.', $this->phpVersion);

        return $parts[0] . '.' . $parts[1];
    }

    public function sapi(): string
    {
        return $this->sapi;
    }

    public function knowsExtensions(): bool
    {
        return $this->extensions !== null;
    }

    public function hasExtension(string $name): bool
    {
        return $this->extensions !== null && in_array(strtolower($name), $this->extensions, true);
    }

    public function knowsIni(): bool
    {
        return $this->ini !== null;
    }

    /**
     * @return string|null null when the setting does not exist in this PHP version
     */
    public function ini(string $key): ?string
    {
        if ($this->ini === null || !array_key_exists($key, $this->ini) || $this->ini[$key] === false) {
            return null;
        }

        return (string) $this->ini[$key];
    }

    public function iniFile(): ?string
    {
        return $this->iniFile;
    }
}
