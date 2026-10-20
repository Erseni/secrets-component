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

#[Table(name: 'secrets.secret_requests')]
#[Index(name: 'secret_requests_expires_at_idx', columns: ['expires_at'])]
#[UniqueConstraint(name: 'secret_requests_token_uq', columns: ['token'])]
#[Entity]
class SecretRequest extends DatabaseEntity
{
    #[Column(type: 'string', length: 64)]
    protected string $token = '';

    /** @var resource|string|null */
    #[Column(type: 'blob')]
    protected $requesterPub;

    /** @var resource|string|null */
    #[Column(type: 'blob', nullable: true)]
    protected $fillerPub = null;

    /** @var resource|string|null */
    #[Column(type: 'blob', nullable: true)]
    protected $ciphertext = null;

    /** @var resource|string|null */
    #[Column(type: 'blob', nullable: true)]
    protected $nonce = null;

    /** @var resource|string|null */
    #[Column(type: 'blob', nullable: true)]
    protected $attachmentCiphertext = null;

    /** @var resource|string|null */
    #[Column(type: 'blob', nullable: true)]
    protected $attachmentNonce = null;

    /** @var resource|string|null */
    #[Column(type: 'blob', nullable: true)]
    protected $attachmentMeta = null;

    #[Column(type: 'integer', options: ['default' => 0])]
    protected int $maxAttachmentBytes = 0;

    #[Column(type: 'datetime')]
    protected DateTime $expiresAt;

    private function readBlob(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }
        if (is_resource($value)) {
            rewind($value);
            return (string) stream_get_contents($value);
        }
        return (string) $value;
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function setToken(string $token): void
    {
        $this->token = $token;
    }

    public function getRequesterPub(): string
    {
        return (string) $this->readBlob($this->requesterPub);
    }

    public function setRequesterPub(string $requesterPub): void
    {
        $this->requesterPub = $requesterPub;
    }

    public function getFillerPub(): ?string
    {
        return $this->readBlob($this->fillerPub);
    }

    public function setFillerPub(?string $fillerPub): void
    {
        $this->fillerPub = $fillerPub;
    }

    public function getCiphertext(): ?string
    {
        return $this->readBlob($this->ciphertext);
    }

    public function setCiphertext(?string $ciphertext): void
    {
        $this->ciphertext = $ciphertext;
    }

    public function getNonce(): ?string
    {
        return $this->readBlob($this->nonce);
    }

    public function setNonce(?string $nonce): void
    {
        $this->nonce = $nonce;
    }

    public function getAttachmentCiphertext(): ?string
    {
        return $this->readBlob($this->attachmentCiphertext);
    }

    public function setAttachmentCiphertext(?string $attachmentCiphertext): void
    {
        $this->attachmentCiphertext = $attachmentCiphertext;
    }

    public function getAttachmentNonce(): ?string
    {
        return $this->readBlob($this->attachmentNonce);
    }

    public function setAttachmentNonce(?string $attachmentNonce): void
    {
        $this->attachmentNonce = $attachmentNonce;
    }

    public function getAttachmentMeta(): ?string
    {
        return $this->readBlob($this->attachmentMeta);
    }

    public function setAttachmentMeta(?string $attachmentMeta): void
    {
        $this->attachmentMeta = $attachmentMeta;
    }

    public function getMaxAttachmentBytes(): int
    {
        return $this->maxAttachmentBytes;
    }

    public function setMaxAttachmentBytes(int $maxAttachmentBytes): void
    {
        $this->maxAttachmentBytes = $maxAttachmentBytes;
    }

    public function getExpiresAt(): DateTime
    {
        return $this->expiresAt;
    }

    public function setExpiresAt(DateTime $expiresAt): void
    {
        $this->expiresAt = $expiresAt;
    }

    public function isFulfilled(): bool
    {
        return $this->fillerPub !== null && $this->ciphertext !== null && $this->nonce !== null;
    }
}
