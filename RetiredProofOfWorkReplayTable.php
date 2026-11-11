<?php

declare(strict_types=1);

namespace esn\components\secrets;

use Doctrine\DBAL\Connection;

final class RetiredProofOfWorkReplayTable
{
    public const string TABLE = 'secrets.pow_used';

    private const string UNQUALIFIED_TABLE = 'pow_used';

    public static function dropIfPresent(Connection $connection): bool
    {
        $schemaManager = $connection->createSchemaManager();
        if (! $schemaManager->tablesExist([self::TABLE]) && ! $schemaManager->tablesExist([self::UNQUALIFIED_TABLE])) {
            return false;
        }

        $schemaManager->dropTable(self::TABLE);

        return true;
    }
}
