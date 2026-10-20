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
            $connection->executeStatement(
                'DELETE FROM secrets.pow_used WHERE expires_at < :now',
                ['now' => $now->format('Y-m-d H:i:s')],
            );

            $connection->executeStatement(
                'INSERT INTO secrets.pow_used (challenge, expires_at, created_at, modified_at) '
                . 'VALUES (:challenge, :expiresAt, :now, :now)',
                [
                    'challenge' => $challenge,
                    'expiresAt' => $expiresAt->format('Y-m-d H:i:s'),
                    'now' => $now->format('Y-m-d H:i:s'),
                ],
            );

            return true;
        } catch (UniqueConstraintViolationException) {
            return false;
        } catch (Throwable $e) {
            $this->secretLogger->logException($e);

            return false;
        }
    }
}
