<?php

declare(strict_types=1);

namespace esn\components\secrets;

interface SecretsApiKeyAuthenticator
{
    public function authenticate(string $presentedKey): ?int;

    public function reserveRequestQuota(int $accountId): SecretsApiQuota;
}
