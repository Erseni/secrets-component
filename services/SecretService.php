<?php

declare(strict_types=1);

namespace esn\components\secrets\services;

use Closure;
use Doctrine\DBAL\Connection;
use DateInterval;
use DateTime;
use DateTimeZone;
use Doctrine\DBAL\ArrayParameterType;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Query\QueryBuilder;
use esn\components\secrets\Base64Url;
use esn\components\secrets\entities\Secret;
use esn\components\secrets\entities\SecretRequest;
use esn\components\secrets\entities\SecretStat;
use esn\components\secrets\entities\SecretStatus;
use esn\components\secrets\SecretLogger;
use esn\components\sse\service\SseService;
use esn\core\database\PostgresConnector;
use esn\core\database\PostgresDml;
use esn\core\Functions;
use esn\core\helper\DateTimeHelper;
use InvalidArgumentException;
use rg\injektor\attributes\Inject;
use rg\injektor\attributes\Param;
use rg\injektor\attributes\Service;
use Throwable;

#[Service]
class SecretService
{
    public const int NONCE_LENGTH = 12;

    public const int PUBKEY_LENGTH = 32;

    public const int MAX_CIPHERTEXT_BYTES = 1048576;

    public const int MAX_ATTACHMENT_META_BYTES = 4096;

    public const int DEFAULT_MAX_ATTACHMENT_BYTES = 0;

    public const int DEFAULT_MAX_TTL_SECONDS = 604800;

    public const int MAX_TTL_SECONDS = 2592000;

    public const int MIN_TTL_SECONDS = 60;

    public const int TOKEN_RAW_BYTES = 16;

    public const int TOKEN_BASE64URL_LENGTH = 22;

    public const int CLEANUP_BATCH_SIZE = 1000;

    public const int CLEANUP_MAX_BATCHES = 50;

    public const int RATE_LIMIT_WRITE_PER_MINUTE = 3;

    public const int POW_DIFFICULTY_BITS = 20;

    public const int POW_WINDOW_SECONDS = 120;

    public const int POW_USED_SKEW_SECONDS = 30;

    public const int RATE_LIMIT_READ_PER_MINUTE = 20;

    public const int RATE_LIMIT_WINDOW_SECONDS = 60;

    public const int RATE_LIMIT_GLOBAL_WRITE_PER_MINUTE = 200;

    public const int RATE_LIMIT_GLOBAL_READ_PER_MINUTE = 500;

    public const int RATE_LIMIT_STATUS_PER_MINUTE = 60;

    public const int RATE_LIMIT_GLOBAL_STATUS_PER_MINUTE = 1000;

    public const int PBKDF2_ITERATIONS = 1200000;

    public const int STATUS_CLEANUP_GRACE_SECONDS = 86400;

    public const string STATUS_WAITING = 'waiting';

    public const string STATUS_FULFILLED = 'fulfilled';

    public const string STATUS_RETRIEVED = 'retrieved';

    public const string STATUS_EXPIRED = 'expired';

    public const string STATUS_GONE = 'gone';

    public const string SSE_EVENT_TYPE = 'status';

    public const array RATE_LIMIT_KEY_PREFIXES = [
        'secrets:create',
        'secrets:retrieve',
        'secrets:create-request',
        'secrets:get-request',
        'secrets:fulfill',
        'secrets:retrieve-fulfillment',
        'secrets:status',
        'secrets:request-status',
    ];

    /** @var PostgresConnector<Secret> */

    #[Inject(overwriteParams: [new Param('name', 'secret'), new Param('class', Secret::class)])]
    protected PostgresConnector $secretConnector;

    /** @var PostgresConnector<SecretRequest> */

    #[Inject(overwriteParams: [new Param('name', 'secretRequest'), new Param('class', SecretRequest::class)])]
    protected PostgresConnector $secretRequestConnector;

    /** @var PostgresConnector<SecretStatus> */

    #[Inject(overwriteParams: [new Param('name', 'secretStatus'), new Param('class', SecretStatus::class)])]
    protected PostgresConnector $secretStatusConnector;

    #[Inject]
    protected SseService $sseService;

    #[Inject]
    protected SecretLogger $secretLogger;

    #[Inject]
    protected SecretsProofOfWorkReplayStore $proofOfWorkReplayStore;

    public function createSecret(
        string $ciphertext,
        string $nonce,
        DateTime $expiresAt,
        ?string $attachmentCiphertext = null,
        ?string $attachmentNonce = null,
        ?string $attachmentMeta = null,
        int $maxAttachmentBytes = self::DEFAULT_MAX_ATTACHMENT_BYTES,
    ): Secret {
        $this->assertNonceLength($nonce);
        $this->assertCiphertextSize($ciphertext);
        $this->assertExpiresWithinWindow($expiresAt);

        $hasAttachment = $attachmentCiphertext !== null || $attachmentNonce !== null || $attachmentMeta !== null;
        if ($hasAttachment) {
            if ($attachmentCiphertext === null || $attachmentNonce === null || $attachmentMeta === null) {
                throw new InvalidArgumentException('Incomplete attachment');
            }
            $this->assertAttachmentSize($attachmentCiphertext, $maxAttachmentBytes);
            $this->assertAttachmentMetaSize($attachmentMeta);
            $this->assertNonceLength($attachmentNonce);
        }

        $secret = new Secret();
        $secret->setToken($this->generateToken());
        $secret->setCiphertext($ciphertext);
        $secret->setNonce($nonce);
        $secret->setExpiresAt($expiresAt);
        $secret->setViewsLeft(1);

        if ($hasAttachment) {
            $secret->setAttachmentCiphertext($attachmentCiphertext);
            $secret->setAttachmentNonce($attachmentNonce);
            $secret->setAttachmentMeta($attachmentMeta);
        }

        $this->secretConnector->create($secret);
        $this->createStatusRow(SecretStatus::KIND_SECRET, $secret->getToken(), $expiresAt);
        $this->incrementStat(SecretStat::METRIC_SECRETS_SENT);

        return $secret;
    }

    public function retrieveAndDelete(string $token): ?Secret
    {
        $connection = $this->secretConnector->getEntityManager()->getConnection();

        $row = SecretDeleteReturning::execute($connection, $token, DateTimeHelper::nowUtcDatabaseString());

        if ($row === false) {
            Functions::logInfo('secrets.retrieve.miss', ['reason' => 'token_miss_or_expired']);

            return null;
        }

        $snapshot = $this->secretSnapshotFromRow($token, $row);

        $this->markStatusRetrieved(SecretStatus::KIND_SECRET, $token);

        return $snapshot;
    }

    public function createRequest(
        string $requesterPub,
        DateTime $expiresAt,
        int $maxAttachmentBytes = self::DEFAULT_MAX_ATTACHMENT_BYTES,
    ): SecretRequest {
        $this->assertPubkeyLength($requesterPub);
        $this->assertExpiresWithinWindow($expiresAt);

        $request = new SecretRequest();
        $request->setToken($this->generateToken());
        $request->setRequesterPub($requesterPub);
        $request->setMaxAttachmentBytes(max(0, $maxAttachmentBytes));
        $request->setExpiresAt($expiresAt);

        $this->secretRequestConnector->create($request);
        $this->createStatusRow(SecretStatus::KIND_REQUEST, $request->getToken(), $expiresAt);
        $this->incrementStat(SecretStat::METRIC_REQUESTS_CREATED);

        return $request;
    }

    public function getRequest(string $token): ?SecretRequest
    {
        $queryBuilder = $this->secretRequestConnector->getQueryBuilder();
        $queryBuilder
            ->andWhere('secretRequest.token = :token')
            ->andWhere('secretRequest.expiresAt > :now')
            ->setParameter('token', $token)
            ->setParameter('now', DateTimeHelper::nowUtc())
            ->setMaxResults(1);

        $results = $this->secretRequestConnector->findByQuery($queryBuilder);
        $request = $results[0] ?? null;

        if (! $request instanceof SecretRequest) {
            Functions::logInfo('secrets.get_request.miss', ['reason' => 'token_miss_or_expired']);

            return null;
        }

        return $request;
    }

    public function fulfillRequest(
        string $token,
        string $fillerPub,
        string $ciphertext,
        string $nonce,
        ?string $attachmentCiphertext = null,
        ?string $attachmentNonce = null,
        ?string $attachmentMeta = null,
        int $maxAttachmentBytes = self::DEFAULT_MAX_ATTACHMENT_BYTES,
    ): bool {
        $this->assertPubkeyLength($fillerPub);
        $this->assertNonceLength($nonce);
        $this->assertCiphertextSize($ciphertext);

        $hasAttachment = $attachmentCiphertext !== null || $attachmentNonce !== null || $attachmentMeta !== null;
        if ($hasAttachment) {
            if ($attachmentCiphertext === null || $attachmentNonce === null || $attachmentMeta === null) {
                throw new InvalidArgumentException('Incomplete attachment');
            }
            $this->assertAttachmentSize($attachmentCiphertext, $maxAttachmentBytes);
            $this->assertAttachmentMetaSize($attachmentMeta);
            $this->assertNonceLength($attachmentNonce);
        }

        $connection = $this->secretRequestConnector->getEntityManager()->getConnection();

        $affectedRows = $connection->createQueryBuilder()
            ->update('secrets.secret_requests')
            ->set('filler_pub', ':fillerPub')
            ->set('ciphertext', ':ciphertext')
            ->set('nonce', ':nonce')
            ->set('attachment_ciphertext', ':attachmentCiphertext')
            ->set('attachment_nonce', ':attachmentNonce')
            ->set('attachment_meta', ':attachmentMeta')
            ->set('modified_at', ':now')
            ->where('token = :token')
            ->andWhere('filler_pub IS NULL')
            ->andWhere('expires_at > :now')
            ->setParameter('fillerPub', $fillerPub, ParameterType::LARGE_OBJECT)
            ->setParameter('ciphertext', $ciphertext, ParameterType::LARGE_OBJECT)
            ->setParameter('nonce', $nonce, ParameterType::LARGE_OBJECT)
            ->setParameter('attachmentCiphertext', $hasAttachment ? $attachmentCiphertext : null, ParameterType::LARGE_OBJECT)
            ->setParameter('attachmentNonce', $hasAttachment ? $attachmentNonce : null, ParameterType::LARGE_OBJECT)
            ->setParameter('attachmentMeta', $hasAttachment ? $attachmentMeta : null, ParameterType::LARGE_OBJECT)
            ->setParameter('token', $token)
            ->setParameter('now', DateTimeHelper::nowUtcDatabaseString())
            ->executeStatement();

        if ($affectedRows === 0) {
            Functions::logInfo('secrets.fulfill.miss', ['reason' => 'token_miss_or_expired_or_already_fulfilled']);

            return false;
        }

        $this->markStatusFulfilled($token);

        return true;
    }

    public function retrieveAndDeleteFulfillment(string $token): ?SecretRequest
    {
        $connection = $this->secretRequestConnector->getEntityManager()->getConnection();

        $delete = $connection->createQueryBuilder()
            ->delete('secrets.secret_requests')
            ->where('token = :token')
            ->andWhere('filler_pub IS NOT NULL')
            ->andWhere('expires_at > :now')
            ->setParameter('token', $token)
            ->setParameter('now', DateTimeHelper::nowUtcDatabaseString());
        $row = PostgresDml::executeReturning(
            $connection,
            $delete,
            ['requester_pub', 'filler_pub', 'ciphertext', 'nonce', 'attachment_ciphertext', 'attachment_nonce', 'attachment_meta', 'expires_at'],
        )->fetchAssociative();

        if ($row === false) {
            Functions::logInfo('secrets.retrieve_fulfillment.miss', ['reason' => 'token_miss_or_expired_or_unfulfilled']);

            return null;
        }

        $snapshot = $this->requestSnapshotFromRow($token, $row);

        $this->markStatusRetrieved(SecretStatus::KIND_REQUEST, $token);

        return $snapshot;
    }

    /**
     * @param  array<string, mixed>  $row
     */
    public function secretSnapshotFromRow(string $token, array $row): Secret
    {
        $snapshot = new Secret();
        $snapshot->setToken($token);
        $snapshot->setCiphertext($this->readBlobField($row['ciphertext']));
        $snapshot->setNonce($this->readBlobField($row['nonce']));
        $snapshot->setAttachmentCiphertext($this->readNullableBlobField($row['attachment_ciphertext'] ?? null));
        $snapshot->setAttachmentNonce($this->readNullableBlobField($row['attachment_nonce'] ?? null));
        $snapshot->setAttachmentMeta($this->readNullableBlobField($row['attachment_meta'] ?? null));
        $snapshot->setExpiresAt(new DateTime((string) $row['expires_at'], new DateTimeZone('UTC')));
        $snapshot->setViewsLeft((int) $row['views_left']);

        return $snapshot;
    }

    /**
     * @param  array<string, mixed>  $row
     */
    public function requestSnapshotFromRow(string $token, array $row): SecretRequest
    {
        $snapshot = new SecretRequest();
        $snapshot->setToken($token);
        $snapshot->setRequesterPub($this->readBlobField($row['requester_pub']));
        $snapshot->setFillerPub($this->readBlobField($row['filler_pub']));
        $snapshot->setCiphertext($this->readBlobField($row['ciphertext']));
        $snapshot->setNonce($this->readBlobField($row['nonce']));
        $snapshot->setAttachmentCiphertext($this->readNullableBlobField($row['attachment_ciphertext'] ?? null));
        $snapshot->setAttachmentNonce($this->readNullableBlobField($row['attachment_nonce'] ?? null));
        $snapshot->setAttachmentMeta($this->readNullableBlobField($row['attachment_meta'] ?? null));
        $snapshot->setExpiresAt(new DateTime((string) $row['expires_at'], new DateTimeZone('UTC')));

        return $snapshot;
    }

    public function cleanupExpired(): CleanupResult
    {
        $connection = $this->secretConnector->getEntityManager()->getConnection();
        $now = DateTimeHelper::nowUtcDatabaseString();

        $expiredSecretTokens = $this->deleteExpiredReturningTokens(
            $connection,
            'secrets.secrets',
            'expires_at < :now',
            ['now' => $now],
        );

        $requestsDeleted = $this->deleteExpired($connection, 'secrets.secret_requests', ['now' => $now]);

        $purgedTokens = $this->deleteExpiredReturningTokens(
            $connection,
            'secrets.secret_status',
            'expires_at < CAST(:now AS timestamp) - make_interval(secs => :grace)',
            ['grace' => self::STATUS_CLEANUP_GRACE_SECONDS, 'now' => $now],
        );

        $powUsedDeleted = $this->drainCount(
            'secrets.pow_used',
            fn(): int => $this->proofOfWorkReplayStore->deleteExpiredBatch($now, self::CLEANUP_BATCH_SIZE),
        );

        $deleted = count($expiredSecretTokens) + $requestsDeleted + count($purgedTokens) + $powUsedDeleted;

        return new CleanupResult($deleted, $purgedTokens, $expiredSecretTokens);
    }

    /**
     * @param  array<string, mixed>  $parameters
     * @return list<string>
     */
    protected function deleteExpiredReturningTokens(Connection $connection, string $table, string $condition, array $parameters): array
    {
        return $this->drainReturningTokens($table, function () use ($connection, $table, $condition, $parameters): array {
            /** @var list<string> */
            return PostgresDml::executeReturning(
                $connection,
                $this->buildBatchDelete($connection, $table, $condition, $parameters),
                ['token'],
            )->fetchFirstColumn();
        });
    }

    /**
     * @param  array<string, mixed>  $parameters
     */
    protected function deleteExpired(Connection $connection, string $table, array $parameters): int
    {
        return $this->drainCount(
            $table,
            fn(): int => (int) $this->buildBatchDelete($connection, $table, 'expires_at < :now', $parameters)->executeStatement(),
        );
    }

    /**
     * @param  Closure(): list<string>  $deleteBatch
     * @return list<string>
     */
    public function drainReturningTokens(string $table, Closure $deleteBatch): array
    {
        $tokens = [];
        for ($batchIndex = 0; $batchIndex < self::CLEANUP_MAX_BATCHES; $batchIndex++) {
            $batch = $deleteBatch();
            foreach ($batch as $token) {
                $tokens[] = $token;
            }

            if (count($batch) < self::CLEANUP_BATCH_SIZE) {
                return $tokens;
            }
        }

        $this->reportCleanupBacklog($table, count($tokens));

        return $tokens;
    }

    /**
     * @param  Closure(): int  $deleteBatch
     */
    public function drainCount(string $table, Closure $deleteBatch): int
    {
        $deleted = 0;
        for ($batchIndex = 0; $batchIndex < self::CLEANUP_MAX_BATCHES; $batchIndex++) {
            $batch = $deleteBatch();
            $deleted += $batch;

            if ($batch < self::CLEANUP_BATCH_SIZE) {
                return $deleted;
            }
        }

        $this->reportCleanupBacklog($table, $deleted);

        return $deleted;
    }

    /**
     * @param  array<string, mixed>  $parameters
     */
    private function buildBatchDelete(Connection $connection, string $table, string $condition, array $parameters): QueryBuilder
    {
        $batch = $connection->createQueryBuilder()
            ->select('id')
            ->from($table)
            ->where($condition)
            ->setMaxResults(self::CLEANUP_BATCH_SIZE);

        return $connection->createQueryBuilder()
            ->delete($table)
            ->where('id IN (' . $batch->getSQL() . ')')
            ->setParameters($parameters);
    }

    private function reportCleanupBacklog(string $table, int $deleted): void
    {
        $this->secretLogger->logWarning('Secrets cleanup stopped at its batch cap, expired rows remain until the next run', [
            'table' => $table,
            'deleted' => $deleted,
            'maxBatches' => self::CLEANUP_MAX_BATCHES,
            'batchSize' => self::CLEANUP_BATCH_SIZE,
        ]);
    }

    /**
     * @return array{kind: string, status: string, createdAt: DateTime, expiresAt: DateTime, fulfilledAt: DateTime|null, retrievedAt: DateTime|null}|null
     */
    public function getSecretStatus(string $token): ?array
    {
        return $this->loadStatus(SecretStatus::KIND_SECRET, $token);
    }

    /**
     * @return array{kind: string, status: string, createdAt: DateTime, expiresAt: DateTime, fulfilledAt: DateTime|null, retrievedAt: DateTime|null}|null
     */
    public function getRequestStatus(string $token): ?array
    {
        return $this->loadStatus(SecretStatus::KIND_REQUEST, $token);
    }

    /**
     * @param  list<string>  $tokens
     * @return array<string, array{kind: string, status: string, createdAt: DateTime, expiresAt: DateTime, fulfilledAt: DateTime|null, retrievedAt: DateTime|null}>
     */
    public function getStatusesByTokens(array $tokens): array
    {
        if ($tokens === []) {
            return [];
        }

        $connection = $this->secretStatusConnector->getEntityManager()->getConnection();

        /** @var list<array{kind: string, token: string, created_at: mixed, expires_at: mixed, fulfilled_at: mixed, retrieved_at: mixed}> $rows */
        $rows = $connection->createQueryBuilder()
            ->select('kind', 'token', 'created_at', 'expires_at', 'fulfilled_at', 'retrieved_at')
            ->from('secrets.secret_status')
            ->where('token IN (:tokens)')
            ->setParameter('tokens', $tokens, ArrayParameterType::STRING)
            ->executeQuery()
            ->fetchAllAssociative();

        $statuses = [];
        foreach ($rows as $row) {
            $kind = $row['kind'];
            $token = $row['token'];
            $expiresAt = $this->readDateTimeField($row['expires_at']);
            $fulfilledAt = $this->readNullableDateTimeField($row['fulfilled_at'] ?? null);
            $retrievedAt = $this->readNullableDateTimeField($row['retrieved_at'] ?? null);

            $statuses[$kind . ':' . $token] = [
                'kind' => $kind,
                'status' => $this->resolveStatus($kind, $expiresAt, $fulfilledAt, $retrievedAt),
                'createdAt' => $this->readDateTimeField($row['created_at']),
                'expiresAt' => $expiresAt,
                'fulfilledAt' => $fulfilledAt,
                'retrievedAt' => $retrievedAt,
            ];
        }

        return $statuses;
    }

    /**
     * @return array{kind: string, status: string, createdAt: DateTime, expiresAt: DateTime, fulfilledAt: DateTime|null, retrievedAt: DateTime|null}|null
     */
    private function loadStatus(string $kind, string $token): ?array
    {
        $connection = $this->secretStatusConnector->getEntityManager()->getConnection();

        $row = $connection->createQueryBuilder()
            ->select('created_at', 'expires_at', 'fulfilled_at', 'retrieved_at')
            ->from('secrets.secret_status')
            ->where('kind = :kind')
            ->andWhere('token = :token')
            ->setParameter('kind', $kind)
            ->setParameter('token', $token)
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchAssociative();

        if ($row === false) {
            return null;
        }

        $createdAt = $this->readDateTimeField($row['created_at']);
        $expiresAt = $this->readDateTimeField($row['expires_at']);
        $fulfilledAt = $this->readNullableDateTimeField($row['fulfilled_at'] ?? null);
        $retrievedAt = $this->readNullableDateTimeField($row['retrieved_at'] ?? null);

        $status = $this->resolveStatus($kind, $expiresAt, $fulfilledAt, $retrievedAt);

        return [
            'kind' => $kind,
            'status' => $status,
            'createdAt' => $createdAt,
            'expiresAt' => $expiresAt,
            'fulfilledAt' => $fulfilledAt,
            'retrievedAt' => $retrievedAt,
        ];
    }

    private function resolveStatus(string $kind, DateTime $expiresAt, ?DateTime $fulfilledAt, ?DateTime $retrievedAt): string
    {
        if ($retrievedAt !== null) {
            return self::STATUS_RETRIEVED;
        }
        if ($expiresAt <= DateTimeHelper::nowUtc()) {
            return self::STATUS_EXPIRED;
        }
        if ($kind === SecretStatus::KIND_REQUEST && $fulfilledAt !== null) {
            return self::STATUS_FULFILLED;
        }
        return self::STATUS_WAITING;
    }

    public function buildPublicChannelSuffix(string $kind, string $token): string
    {
        $prefix = $kind === SecretStatus::KIND_REQUEST ? 'secret-request' : 'secret';
        return sprintf('%s:%s', $prefix, $token);
    }

    private function createStatusRow(string $kind, string $token, DateTime $expiresAt): void
    {
        try {
            $status = new SecretStatus();
            $status->setKind($kind);
            $status->setToken($token);
            $status->setExpiresAt($expiresAt);
            $this->secretStatusConnector->create($status);
        } catch (Throwable $e) {
            $this->secretLogger->logException($e);
            Functions::logWarning('secrets.status.create.failed', ['kind' => $kind]);
        }
    }

    private function incrementStat(string $metric): void
    {
        try {
            $connection = $this->secretConnector->getEntityManager()->getConnection();
            $insert = $connection->createQueryBuilder()
                ->insert('secrets.secret_stats')
                ->setValue('metric', ':metric')
                ->setValue('count', '1')
                ->setValue('created_at', ':now')
                ->setValue('modified_at', ':now')
                ->setParameter('metric', $metric)
                ->setParameter('now', DateTimeHelper::nowUtcDatabaseString());
            PostgresDml::upsert($connection, $insert, ['metric'], [
                'count' => PostgresDml::incrementExisting('secret_stats', 'count'),
                'modified_at' => PostgresDml::excluded('modified_at'),
            ]);
        } catch (Throwable $e) {
            $this->secretLogger->logException($e);
        }
    }

    private function markStatusFulfilled(string $token): void
    {
        try {
            $connection = $this->secretStatusConnector->getEntityManager()->getConnection();
            $row = PostgresDml::executeReturning(
                $connection,
                $this->buildStatusTransition($connection, SecretStatus::KIND_REQUEST, $token, 'fulfilled_at'),
                ['fulfilled_at'],
            )->fetchAssociative();

            if ($row === false) {
                return;
            }

            $this->publishStatusEvent(SecretStatus::KIND_REQUEST, $token);
        } catch (Throwable $e) {
            $this->secretLogger->logException($e);
            Functions::logWarning('secrets.status.update.failed', ['kind' => SecretStatus::KIND_REQUEST, 'transition' => 'fulfilled']);
        }
    }

    private function markStatusRetrieved(string $kind, string $token): void
    {
        try {
            $connection = $this->secretStatusConnector->getEntityManager()->getConnection();
            $row = PostgresDml::executeReturning(
                $connection,
                $this->buildStatusTransition($connection, $kind, $token, 'retrieved_at'),
                ['retrieved_at'],
            )->fetchAssociative();

            if ($row === false) {
                return;
            }

            $this->publishStatusEvent($kind, $token);
        } catch (Throwable $e) {
            $this->secretLogger->logException($e);
            Functions::logWarning('secrets.status.update.failed', ['kind' => $kind, 'transition' => 'retrieved']);
        }
    }

    private function buildStatusTransition(Connection $connection, string $kind, string $token, string $column): QueryBuilder
    {
        return $connection->createQueryBuilder()
            ->update('secrets.secret_status')
            ->set($column, ':now')
            ->set('modified_at', ':now')
            ->where('kind = :kind')
            ->andWhere('token = :token')
            ->andWhere($column . ' IS NULL')
            ->setParameter('kind', $kind)
            ->setParameter('token', $token)
            ->setParameter('now', DateTimeHelper::nowUtcDatabaseString());
    }

    public function publicChannelExists(string $kind, string $token): bool
    {
        try {
            $connection = $this->secretStatusConnector->getEntityManager()->getConnection();
            $row = $connection->createQueryBuilder()
                ->select('1')
                ->from('secrets.secret_status')
                ->where('kind = :kind')
                ->andWhere('token = :token')
                ->andWhere('expires_at > :now')
                ->andWhere('retrieved_at IS NULL')
                ->setParameter('kind', $kind)
                ->setParameter('token', $token)
                ->setParameter('now', DateTimeHelper::nowUtcDatabaseString())
                ->setMaxResults(1)
                ->executeQuery()
                ->fetchOne();
            return $row !== false;
        } catch (Throwable $e) {
            $this->secretLogger->logException($e);
            return false;
        }
    }

    private function publishStatusEvent(string $kind, string $token): void
    {
        $payload = $this->loadStatus($kind, $token);
        if ($payload === null) {
            return;
        }

        try {
            $channel = $this->sseService->buildPublicChannel($this->buildPublicChannelSuffix($kind, $token));
        } catch (Throwable $e) {
            $this->secretLogger->logException($e);
            return;
        }

        $this->sseService->sendEvent($channel, self::SSE_EVENT_TYPE, [
            'status' => $payload['status'],
            'kind' => $kind,
            'created_at' => $payload['createdAt']->format(DATE_ATOM),
            'expires_at' => $payload['expiresAt']->format(DATE_ATOM),
            'fulfilled_at' => $payload['fulfilledAt']?->format(DATE_ATOM),
            'retrieved_at' => $payload['retrievedAt']?->format(DATE_ATOM),
        ]);
    }

    private function readDateTimeField(mixed $value): DateTime
    {
        return new DateTime((string) $value, new DateTimeZone('UTC'));
    }

    private function readNullableDateTimeField(mixed $value): ?DateTime
    {
        if ($value === null || $value === '') {
            return null;
        }
        return new DateTime((string) $value, new DateTimeZone('UTC'));
    }

    public function generateToken(): string
    {
        return Base64Url::encode(random_bytes(self::TOKEN_RAW_BYTES));
    }

    private function assertNonceLength(string $nonce): void
    {
        if (strlen($nonce) !== self::NONCE_LENGTH) {
            throw new InvalidArgumentException('Invalid nonce length');
        }
    }

    private function assertPubkeyLength(string $pubkey): void
    {
        if (strlen($pubkey) !== self::PUBKEY_LENGTH) {
            throw new InvalidArgumentException('Invalid public key length');
        }
    }

    private function assertCiphertextSize(string $ciphertext): void
    {
        $len = strlen($ciphertext);
        if ($len === 0 || $len > self::MAX_CIPHERTEXT_BYTES) {
            throw new InvalidArgumentException('Invalid ciphertext size');
        }
    }

    private function assertAttachmentSize(string $attachmentCiphertext, int $maxBytes): void
    {
        if ($maxBytes <= 0) {
            throw new InvalidArgumentException('Attachments are not allowed');
        }
        $len = strlen($attachmentCiphertext);
        if ($len === 0 || $len > $maxBytes) {
            throw new InvalidArgumentException('Invalid attachment size');
        }
    }

    private function assertAttachmentMetaSize(string $attachmentMeta): void
    {
        $len = strlen($attachmentMeta);
        if ($len === 0 || $len > self::MAX_ATTACHMENT_META_BYTES) {
            throw new InvalidArgumentException('Invalid attachment meta size');
        }
    }

    private function assertExpiresWithinWindow(DateTime $expiresAt): void
    {
        $now = DateTimeHelper::nowUtc();
        if ($expiresAt <= $now) {
            throw new InvalidArgumentException('expiresAt must be in the future');
        }
        $maxExpiry = (clone $now)->add(new DateInterval('PT' . self::MAX_TTL_SECONDS . 'S'));
        if ($expiresAt > $maxExpiry) {
            throw new InvalidArgumentException('expiresAt exceeds maximum TTL');
        }
    }

    private function readBlobField(mixed $value): string
    {
        if (is_resource($value)) {
            rewind($value);

            return (string) stream_get_contents($value);
        }

        return (string) $value;
    }

    private function readNullableBlobField(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        return $this->readBlobField($value);
    }
}
