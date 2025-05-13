<?php

namespace HttpSignature\Tests\Helpers;

class RawHttpBuilder
{
    public static function fromParts(string $method, string $path, array $headers = [], string $body = ''): string
    {
        $lines = [];
        $lines[] = sprintf('%s %s HTTP/1.1', strtoupper($method), $path);

        foreach ($headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }

        // Normalize and return with CRLF line endings
        $raw = implode("\n", $lines) . "\n\n" . $body;
        $raw = str_replace("\r", '', $raw);      // Strip any pre-existing \r
        $raw = str_replace("\n", "\r\n", $raw);  // Replace \n with \r\n

        return $raw;
    }
}

