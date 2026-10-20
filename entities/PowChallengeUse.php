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

#[Table(name: 'secrets.pow_used')]
#[Index(name: 'pow_used_expires_at_idx', columns: ['expires_at'])]
#[UniqueConstraint(name: 'pow_used_challenge_uq', columns: ['challenge'])]
#[Entity]
class PowChallengeUse extends DatabaseEntity
{
    #[Column(type: 'string', length: 64)]
    protected string $challenge = '';

    #[Column(type: 'datetime')]
    protected DateTime $expiresAt;

    public function getChallenge(): string
    {
        return $this->challenge;
    }

    public function setChallenge(string $challenge): void
    {
        $this->challenge = $challenge;
    }

    public function getExpiresAt(): DateTime
    {
        return $this->expiresAt;
    }

    public function setExpiresAt(DateTime $expiresAt): void
    {
        $this->expiresAt = $expiresAt;
    }
}
