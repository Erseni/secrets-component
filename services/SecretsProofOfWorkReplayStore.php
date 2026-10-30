<?php

declare(strict_types=1);

namespace esn\components\secrets\services;

use DateInterval;
use DateTime;
use DateTimeZone;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use esn\components\secrets\entities\PowChallengeUse;
use esn\components\secrets\SecretLogger;
use esn\core\database\PostgresConnector;
use esn\core\security\ProofOfWorkReplayStore;
use rg\injektor\attributes\Inject;
use rg\injektor\attributes\Param;
use rg\injektor\attributes\Service;
use Throwable;

#[Service]
class SecretsProofOfWorkReplayStore implements ProofOfWorkReplayStore
{
    private const string TABLE = 'secrets.pow_used';

    /** @var PostgresConnector<PowChallengeUse> */
    #[Inject(overwriteParams: [new Param('name', 'powChallengeUse'), new Param('class', PowChallengeUse::class)])]
    protected PostgresConnector $powChallengeUseConnector;

    #[Inject]
    protected SecretLogger $secretLogger;

    public function markUsed(string $challenge, int $ttlSeconds): bool
    {
        $now = new DateTime('now', new DateTimeZone('UTC'));
        $expiresAt = clone $now;
        $expiresAt->add(new DateInterval('PT' . ($ttlSeconds + SecretService::POW_USED_SKEW_SECONDS) . 'S'));

        $connection = $this->powChallengeUseConnector->getEntityManager()->getConnection();

        try {
            $connection->createQueryBuilder()
                ->delete(self::TABLE)
                ->where('expires_at < :now')
                ->setParameter('now', $now->format('Y-m-d H:i:s'))
                ->executeStatement();

            $connection->createQueryBuilder()
                ->insert(self::TABLE)
                ->setValue('challenge', ':challenge')
                ->setValue('expires_at', ':expiresAt')
                ->setValue('created_at', ':now')
                ->setValue('modified_at', ':now')
                ->setParameter('challenge', $challenge)
                ->setParameter('expiresAt', $expiresAt->format('Y-m-d H:i:s'))
                ->setParameter('now', $now->format('Y-m-d H:i:s'))
                ->executeStatement();

            return true;
        } catch (UniqueConstraintViolationException) {
            return false;
        } catch (Throwable $e) {
            $this->secretLogger->logException($e);

            return false;
        }
    }

    public function deleteExpiredBatch(string $nowUtc, int $limit): int
    {
        $connection = $this->powChallengeUseConnector->getEntityManager()->getConnection();
        $batch = $connection->createQueryBuilder()
            ->select('id')
            ->from(self::TABLE)
            ->where('expires_at < :now')
            ->setMaxResults($limit);

        return (int) $connection->createQueryBuilder()
            ->delete(self::TABLE)
            ->where('id IN (' . $batch->getSQL() . ')')
            ->setParameter('now', $nowUtc)
            ->executeStatement();
    }
}
