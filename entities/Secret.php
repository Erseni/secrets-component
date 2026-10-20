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

#[Table(name: 'secrets.secrets')]
#[Index(name: 'secrets_expires_at_idx', columns: ['expires_at'])]
#[UniqueConstraint(name: 'secrets_token_uq', columns: ['token'])]
#[Entity]
class Secret extends DatabaseEntity
{
    #[Column(type: 'string', length: 64)]
    protected string $token = '';

    /** @var resource|string|null */
    #[Column(type: 'blob')]
    protected $ciphertext;

    /** @var resource|string|null */
    #[Column(type: 'blob')]
    protected $nonce;

    /** @var resource|string|null */
    #[Column(type: 'blob', nullable: true)]
    protected $attachmentCiphertext = null;

    /** @var resource|string|null */
    #[Column(type: 'blob', nullable: true)]
    protected $attachmentNonce = null;

    /** @var resource|string|null */
    #[Column(type: 'blob', nullable: true)]
    protected $attachmentMeta = null;

    #[Column(type: 'datetime')]
    protected DateTime $expiresAt;

    #[Column(type: 'smallint', options: ['check' => 'views_left >= 0'])]
    protected int $viewsLeft = 1;

    public function getToken(): string
    {
        return $this->token;
    }

    public function setToken(string $token): void
    {
        $this->token = $token;
    }

    public function getCiphertext(): string
    {
        if (is_resource($this->ciphertext)) {
            rewind($this->ciphertext);
            return (string) stream_get_contents($this->ciphertext);
        }
        return (string) $this->ciphertext;
    }

    public function setCiphertext(string $ciphertext): void
    {
        $this->ciphertext = $ciphertext;
    }

    public function getNonce(): string
    {
        if (is_resource($this->nonce)) {
            rewind($this->nonce);
            return (string) stream_get_contents($this->nonce);
        }
        return (string) $this->nonce;
    }

    public function setNonce(string $nonce): void
    {
        $this->nonce = $nonce;
    }

    public function getAttachmentCiphertext(): ?string
    {
        if (is_resource($this->attachmentCiphertext)) {
            rewind($this->attachmentCiphertext);
            return (string) stream_get_contents($this->attachmentCiphertext);
        }
        if ($this->attachmentCiphertext === null) {
            return null;
        }
        return (string) $this->attachmentCiphertext;
    }

    public function setAttachmentCiphertext(?string $attachmentCiphertext): void
    {
        $this->attachmentCiphertext = $attachmentCiphertext;
    }

    public function getAttachmentNonce(): ?string
    {
        if (is_resource($this->attachmentNonce)) {
            rewind($this->attachmentNonce);
            return (string) stream_get_contents($this->attachmentNonce);
        }
        if ($this->attachmentNonce === null) {
            return null;
        }
        return (string) $this->attachmentNonce;
    }

    public function setAttachmentNonce(?string $attachmentNonce): void
    {
        $this->attachmentNonce = $attachmentNonce;
    }

    public function getAttachmentMeta(): ?string
    {
        if (is_resource($this->attachmentMeta)) {
            rewind($this->attachmentMeta);
            return (string) stream_get_contents($this->attachmentMeta);
        }
        if ($this->attachmentMeta === null) {
            return null;
        }
        return (string) $this->attachmentMeta;
    }

    public function setAttachmentMeta(?string $attachmentMeta): void
    {
        $this->attachmentMeta = $attachmentMeta;
    }

    public function getExpiresAt(): DateTime
    {
        return $this->expiresAt;
    }

    public function setExpiresAt(DateTime $expiresAt): void
    {
        $this->expiresAt = $expiresAt;
    }

    public function getViewsLeft(): int
    {
        return $this->viewsLeft;
    }

    public function setViewsLeft(int $viewsLeft): void
    {
        $this->viewsLeft = $viewsLeft;
    }
}
