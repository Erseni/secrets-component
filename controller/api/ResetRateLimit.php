<?php

declare(strict_types=1);

namespace esn\components\secrets\controller\api;

use esn\components\secrets\services\SecretService;
use esn\core\http\Http;
use esn\core\http\Route;
use esn\core\security\AbstractResetRateLimit;
use rg\injektor\attributes\Service;

#[Service]
class ResetRateLimit extends AbstractResetRateLimit
{
    public function getRoutes(): array
    {
        return [
            new Route(Http::METHOD_POST, '/api/secrets/test/reset-rate-limit'),
        ];
    }

    protected function getRateLimitKeyPrefixes(): array
    {
        return SecretService::RATE_LIMIT_KEY_PREFIXES;
    }
}
