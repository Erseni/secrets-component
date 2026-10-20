<?php

declare(strict_types=1);

namespace esn\components\secrets\forms;

use esn\components\secrets\Base64Url;
use esn\components\secrets\services\SecretService;
use esn\core\helper\StringHelper;
use Symfony\Component\HttpFoundation\ParameterBag;

final class SecretsValidators
{
    public static function validateBase64(mixed $value, int $minBytes, int $maxBytes): ?string
    {
        if (!StringHelper::isString($value)) {
            return 'Must be a string';
        }
        $decoded = Base64Url::decode($value);
        if ($decoded === null) {
            return 'Must be valid base64';
        }
        $len = strlen($decoded);
        if ($len < $minBytes || $len > $maxBytes) {
            return 'Invalid byte length';
        }
        return null;
    }

    public static function validateBase64Exact(mixed $value, int $expectedBytes): ?string
    {
        if (!StringHelper::isString($value)) {
            return 'Must be a string';
        }
        $decoded = Base64Url::decode($value);
        if ($decoded === null) {
            return 'Must be valid base64';
        }
        if (strlen($decoded) !== $expectedBytes) {
            return 'Expected ' . $expectedBytes . ' bytes';
        }
        return null;
    }

    /**
     * @return array<string, string>
     */
    public static function validateAttachmentFields(ParameterBag $body, int $maxAttachmentBytes): array
    {
        $errors = [];

        $attachmentCiphertext = $body->get('attachment_ciphertext');
        $attachmentNonce = $body->get('attachment_nonce');
        $attachmentMeta = $body->get('attachment_meta');

        $hasAttachment = $attachmentCiphertext !== null || $attachmentNonce !== null || $attachmentMeta !== null;
        if (! $hasAttachment) {
            return $errors;
        }

        if ($maxAttachmentBytes <= 0) {
            $errors['attachment'] = 'attachments_not_allowed';

            return $errors;
        }

        if ($attachmentCiphertext === null) {
            $errors['attachment_ciphertext'] = 'Required when attachment present';
        } else {
            $ciphertextError = self::exceedsEncodedLimit($attachmentCiphertext, $maxAttachmentBytes)
                ? 'Invalid byte length'
                : self::validateBase64($attachmentCiphertext, 1, $maxAttachmentBytes);
            if ($ciphertextError !== null) {
                $errors['attachment_ciphertext'] = $ciphertextError;
            }
        }

        if ($attachmentNonce === null) {
            $errors['attachment_nonce'] = 'Required when attachment present';
        } else {
            $nonceError = self::validateBase64Exact($attachmentNonce, SecretService::NONCE_LENGTH);
            if ($nonceError !== null) {
                $errors['attachment_nonce'] = $nonceError;
            }
        }

        if ($attachmentMeta === null) {
            $errors['attachment_meta'] = 'Required when attachment present';
        } else {
            $metaError = self::exceedsEncodedLimit($attachmentMeta, SecretService::MAX_ATTACHMENT_META_BYTES)
                ? 'Invalid byte length'
                : self::validateBase64($attachmentMeta, 1, SecretService::MAX_ATTACHMENT_META_BYTES);
            if ($metaError !== null) {
                $errors['attachment_meta'] = $metaError;
            }
        }

        return $errors;
    }

    public static function validateBoolean(mixed $value): ?string
    {
        if ($value === null || $value === '' || is_bool($value)) {
            return null;
        }
        if ($value === 0 || $value === 1 || $value === '0' || $value === '1') {
            return null;
        }

        return 'Must be a boolean';
    }

    public static function isTruthyBoolean(mixed $value): bool
    {
        return $value === true || $value === 1 || $value === '1';
    }

    private static function exceedsEncodedLimit(mixed $value, int $maxBytes): bool
    {
        if (! StringHelper::isString($value)) {
            return false;
        }

        return strlen($value) > intdiv($maxBytes * 4, 3) + 4;
    }

    public static function validateTtl(mixed $value, int $maxSeconds = SecretService::DEFAULT_MAX_TTL_SECONDS): ?string
    {
        if (!is_numeric($value)) {
            return 'Must be a number';
        }
        $int = (int) $value;
        if ($int < 60 || $int > $maxSeconds) {
            return 'ttl_seconds out of range';
        }
        return null;
    }
}
