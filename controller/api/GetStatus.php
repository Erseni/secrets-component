<?php

declare(strict_types=1);

namespace esn\components\secrets\controller\api;

use esn\components\secrets\SecretLogger;
use esn\components\secrets\services\SecretService;
use esn\core\http\ApiApplication;
use esn\core\http\Http;
use esn\core\http\RateLimit;
use esn\core\http\RateLimitConfig;
use esn\core\http\Route;
use esn\core\security\PubliclyAccessibleEndpoint;
use rg\injektor\attributes\Inject;
use rg\injektor\attributes\Service;
use Throwable;

#[Service]
class GetStatus extends ApiApplication implements RateLimit, PubliclyAccessibleEndpoint
{
    #[Inject]
    protected SecretService $secretService;

    #[Inject]
    protected SecretLogger $secretLogger;

    public function getRoutes(): array
    {
        return [
            new Route(Http::METHOD_GET, '/api/secrets/{token:[A-Za-z0-9_-]{22}}/status'),
        ];
    }

    public function hasAccess(): bool
    {
        return true;
    }

    public function getRateLimit(): RateLimitConfig
    {
        return new RateLimitConfig(
            keyPrefix: 'secrets:status',
            perIpLimit: SecretService::RATE_LIMIT_STATUS_PER_MINUTE,
            globalLimit: SecretService::RATE_LIMIT_GLOBAL_STATUS_PER_MINUTE,
            windowSeconds: SecretService::RATE_LIMIT_WINDOW_SECONDS,
            recordOnlyOnSuccess: false,
        );
    }

    public function getData(): array
    {
        try {
            $token = (string) $this->request->getPathParam('token');
            $status = $this->secretService->getSecretStatus($token);

            if ($status === null) {
                $this->httpStatusCode = Http::NOT_FOUND;

                return $this->showErrorMessage('Not found');
            }

            return [
                'status' => $status['status'],
                'kind' => $status['kind'],
                'created_at' => $status['createdAt']->format(DATE_ATOM),
                'expires_at' => $status['expiresAt']->format(DATE_ATOM),
                'retrieved_at' => $status['retrievedAt']?->format(DATE_ATOM),
            ];
        } catch (Throwable $e) {
            $this->secretLogger->logException($e);

            return $this->showErrorMessage('Unable to load status');
        }
    }
}
