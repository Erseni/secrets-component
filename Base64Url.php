<?php

declare(strict_types=1);

namespace esn\components\secrets;

final class Base64Url
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function decode(string $text): ?string
    {
        $translated = strtr($text, '-_', '+/');
        $padding = (4 - strlen($translated) % 4) % 4;
        if ($padding === 3) {
            return null;
        }
        $padded = $translated . str_repeat('=', $padding);
        $decoded = base64_decode($padded, true);
        if ($decoded === false) {
            return null;
        }
        return $decoded;
    }
}
