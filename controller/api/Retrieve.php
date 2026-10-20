<?php

declare(strict_types=1);

namespace esn\components\secrets\controller\api;

use esn\components\secrets\Base64Url;
use esn\components\secrets\SecretLogger;
use esn\components\secrets\SecretsHookDispatchTrait;
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
class Retrieve extends ApiApplication implements RateLimit, PubliclyAccessibleEndpoint
{
    use SecretsHookDispatchTrait;

    #[Inject]
    protected SecretService $secretService;

    #[Inject]
    protected SecretLogger $secretLogger;

    public function getRoutes(): array
    {
        return [
            new Route(Http::METHOD_POST, '/api/secrets/{token:[A-Za-z0-9_-]{22}}/retrieve'),
        ];
    }

    public function hasAccess(): bool
    {
        return true;
    }

    public function getRateLimit(): RateLimitConfig
    {
        return new RateLimitConfig(
            keyPrefix: 'secrets:retrieve',
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
            $secret = $this->secretService->retrieveAndDelete($token);

            if ($secret === null) {
                $this->httpStatusCode = Http::NOT_FOUND;

                return $this->showErrorMessage('Not found');
            }

            $this->notifyStatusChanged($token, SecretService::STATUS_RETRIEVED);

            $response = [
                'ciphertext' => Base64Url::encode($secret->getCiphertext()),
                'nonce' => Base64Url::encode($secret->getNonce()),
            ];

            $attachmentCiphertext = $secret->getAttachmentCiphertext();
            $attachmentNonce = $secret->getAttachmentNonce();
            $attachmentMeta = $secret->getAttachmentMeta();

            if ($attachmentCiphertext !== null && $attachmentNonce !== null && $attachmentMeta !== null) {
                $response['attachment_ciphertext'] = Base64Url::encode($attachmentCiphertext);
                $response['attachment_nonce'] = Base64Url::encode($attachmentNonce);
                $response['attachment_meta'] = Base64Url::encode($attachmentMeta);
            }

            return $response;
        } catch (Throwable $e) {
            $this->secretLogger->logException($e);

            return $this->showErrorMessage('Unable to retrieve secret');
        }
    }
}
