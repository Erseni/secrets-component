<?php

declare(strict_types=1);

namespace esn\components\secrets;

use esn\core\http\Http;

/**
 * @property \esn\core\http\Request $request
 * @property \esn\components\secrets\services\SecretsApiKeyService $secretsApiKeyService
 */
trait SecretsApiKeyAccessTrait
{
    protected function shouldBypassProofOfWork(): bool
    {
        if ($this->secretsApiKeyService->extractPresentedKey($this->request) !== null) {
            return true;
        }

        return parent::shouldBypassProofOfWork();
    }

    protected function shouldBypassRateLimit(): bool
    {
        if ($this->secretsApiKeyService->authenticateRequest($this->request) !== null) {
            return true;
        }

        return parent::shouldBypassRateLimit();
    }

    /**
     * @return array<string, string>
     */
    private function validateApiKey(): array
    {
        if ($this->secretsApiKeyService->extractPresentedKey($this->request) !== null
            && $this->secretsApiKeyService->authenticateRequest($this->request) === null) {
            $this->httpStatusCode = Http::UNAUTHORIZED;

            return ['api_key' => 'Invalid API key'];
        }

        return [];
    }

    /**
     * @return array<string, string>|null
     */
    private function reserveApiKeyQuota(): ?array
    {
        $apiAccountId = $this->secretsApiKeyService->authenticateRequest($this->request);
        if ($apiAccountId === null) {
            return null;
        }

        $quota = $this->secretsApiKeyService->reserveRequestQuota($apiAccountId);
        if ($quota->allowed) {
            return null;
        }

        $this->httpStatusCode = Http::TOO_MANY_REQUESTS;
        $this->responseHeaders['Retry-After'] = (string) $quota->retryAfterSeconds;

        return $this->showErrorMessage('API key quota exhausted');
    }
}
