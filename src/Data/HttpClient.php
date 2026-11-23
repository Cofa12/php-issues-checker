<?php

declare(strict_types=1);

namespace PhpIssuesChecker\Data;

/**
 * Minimal JSON-over-HTTPS client (curl when available, PHP streams otherwise).
 */
class HttpClient
{
    private int $timeout;

    public function __construct(int $timeout = 8)
    {
        $this->timeout = $timeout;
    }

    /**
     * @param array<string, string> $headers
     *
     * @return mixed decoded JSON
     */
    public function getJson(string $url, array $headers = [])
    {
        $headers += [
            'Accept' => 'application/json',
            'User-Agent' => 'php-issues-checker',
        ];
        $lines = [];
        foreach ($headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }

        $body = function_exists('curl_init') ? $this->viaCurl($url, $lines) : $this->viaStreams($url, $lines);

        $data = json_decode($body, true);
        if (!is_array($data)) {
            throw new \RuntimeException(sprintf('Invalid JSON received from %s', $url));
        }

        return $data;
    }

    /** @param string[] $headers */
    private function viaCurl(string $url, array $headers): string
    {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new \RuntimeException(sprintf('Could not start a request to %s', $url));
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_TIMEOUT => $this->timeout * 2,
            CURLOPT_HTTPHEADER => $headers,
        ]);
        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        if (PHP_VERSION_ID < 80000) {
            curl_close($ch); // no-op since PHP 8, deprecated in 8.5
        }

        if (!is_string($body) || $status >= 400 || $status === 0) {
            throw new \RuntimeException(sprintf('Request to %s failed (HTTP %d) %s', $url, $status, $error));
        }

        return $body;
    }

    /** @param string[] $headers */
    private function viaStreams(string $url, array $headers): string
    {
        if (!filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN)) {
            throw new \RuntimeException('Neither ext-curl nor allow_url_fopen is available.');
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => implode("\r\n", $headers),
                'timeout' => $this->timeout,
                'ignore_errors' => false,
            ],
        ]);

        $body = @file_get_contents($url, false, $context);
        if (!is_string($body)) {
            throw new \RuntimeException(sprintf('Request to %s failed.', $url));
        }

        return $body;
    }
}
