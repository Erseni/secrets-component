<?php

declare(strict_types=1);

namespace esn\components\secrets\services;

readonly class CleanupResult
{
    /**
     * @param  list<string>  $purgedTokens
     * @param  list<string>  $expiredSecretTokens
     */
    public function __construct(
        public int $deleted,
        public array $purgedTokens,
        public array $expiredSecretTokens = [],
    ) {}
}
