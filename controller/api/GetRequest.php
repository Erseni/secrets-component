<?php

declare(strict_types=1);

namespace esn\components\secrets\controller\api;

use esn\components\secrets\Base64Url;
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
class GetRequest extends ApiApplication implements RateLimit, PubliclyAccessibleEndpoint
{
    #[Inject]
    protected SecretService $secretService;

    #[Inject]
    protected SecretLogger $secretLogger;

    public function getRoutes(): array
    {
        return [
            new Route(Http::METHOD_GET, '/api/secrets/requests/{token:[A-Za-z0-9_-]{22}}'),
        ];
    }

    public function hasAccess(): bool
    {
        return true;
    }

    public function getRateLimit(): RateLimitConfig
    {
        return new RateLimitConfig(
            keyPrefix: 'secrets:get-request',
            perIpLimit: SecretService::RATE_LIMIT_READ_PER_MINUTE,
            globalLimit: SecretService::RATE_LIMIT_GLOBAL_READ_PER_MINUTE,
            windowSeconds: SecretService::RATE_LIMIT_WINDOW_SECONDS,
            recordOnlyOnSuccess: false,
        );
    }

    public function getData(): array
    {
        try {
            $token = (string) $this->request->getPathParam('token');
            $request = $this->secretService->getRequest($token);

            if ($request === null) {
                $this->httpStatusCode = Http::NOT_FOUND;

                return $this->showErrorMessage('Not found');
            }

            return [
                'requester_pub' => Base64Url::encode($request->getRequesterPub()),
                'expires_at' => $request->getExpiresAt()->format(DATE_ATOM),
                'max_attachment_bytes' => $request->getMaxAttachmentBytes(),
            ];
        } catch (Throwable $e) {
            $this->secretLogger->logException($e);

            return $this->showErrorMessage('Unable to load secret request');
        }
    }
}
