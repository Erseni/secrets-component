<?php

declare(strict_types=1);

namespace esn\components\secrets;

final readonly class SecretsApiQuota
{
    public function __construct(
        public bool $allowed,
        public int $retryAfterSeconds = 0,
    ) {}

    public static function allow(): self
    {
        return new self(true);
    }

    public static function deny(int $retryAfterSeconds): self
    {
        return new self(false, max(1, $retryAfterSeconds));
    }
}
