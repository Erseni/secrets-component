<?php

declare(strict_types=1);

namespace esn\components\secrets\services;

use Doctrine\DBAL\Connection;

final class SecretDeleteReturning
{
    private const string SQL = 'DELETE FROM secrets.secrets'
        . ' WHERE token = :token AND expires_at > :now'
        . ' RETURNING ciphertext, nonce, attachment_ciphertext, attachment_nonce, attachment_meta, expires_at, views_left';

    /**
     * @return array<string, mixed>|false
     */
    public static function execute(Connection $connection, string $token, string $nowUtc): array|false
    {
        return $connection->executeQuery(self::SQL, ['token' => $token, 'now' => $nowUtc])->fetchAssociative();
    }
}
