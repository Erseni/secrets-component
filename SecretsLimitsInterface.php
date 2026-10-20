<?php

declare(strict_types=1);

namespace esn\components\secrets;

interface SecretsLimitsInterface
{
    public function getMaxTtlSeconds(): int;

    public function isLongTtlEnabled(): bool;

    public function getMaxAttachmentBytes(): int;
}
