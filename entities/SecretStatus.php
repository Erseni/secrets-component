<?php

declare(strict_types=1);

namespace esn\components\secrets\entities;

use DateTime;
use Doctrine\ORM\Mapping\Column;
use Doctrine\ORM\Mapping\Entity;
use Doctrine\ORM\Mapping\Index;
use Doctrine\ORM\Mapping\Table;
use Doctrine\ORM\Mapping\UniqueConstraint;
use esn\core\database\DatabaseEntity;

#[Table(name: 'secrets.secret_status')]
#[Index(name: 'secret_status_expires_at_idx', columns: ['expires_at'])]
#[UniqueConstraint(name: 'secret_status_kind_token_uq', columns: ['kind', 'token'])]
#[Entity]
class SecretStatus extends DatabaseEntity
{
    public const string KIND_SECRET = 'secret';

    public const string KIND_REQUEST = 'request';

    #[Column(type: 'string', length: 16)]
    protected string $kind = self::KIND_SECRET;

    #[Column(type: 'string', length: 64)]
    protected string $token = '';

    #[Column(type: 'datetime')]
    protected DateTime $expiresAt;

    #[Column(type: 'datetime', nullable: true)]
    protected ?DateTime $fulfilledAt = null;

    #[Column(type: 'datetime', nullable: true)]
    protected ?DateTime $retrievedAt = null;

    public function getKind(): string
    {
        return $this->kind;
    }

    public function setKind(string $kind): void
    {
        $this->kind = $kind;
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function setToken(string $token): void
    {
        $this->token = $token;
    }

    public function getExpiresAt(): DateTime
    {
        return $this->expiresAt;
    }

    public function setExpiresAt(DateTime $expiresAt): void
    {
        $this->expiresAt = $expiresAt;
    }

    public function getFulfilledAt(): ?DateTime
    {
        return $this->fulfilledAt;
    }

    public function setFulfilledAt(?DateTime $fulfilledAt): void
    {
        $this->fulfilledAt = $fulfilledAt;
    }

    public function getRetrievedAt(): ?DateTime
    {
        return $this->retrievedAt;
    }

    public function setRetrievedAt(?DateTime $retrievedAt): void
    {
        $this->retrievedAt = $retrievedAt;
    }
}
