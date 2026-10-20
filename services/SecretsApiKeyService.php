<?php

declare(strict_types=1);

namespace esn\components\secrets\services;

use esn\components\secrets\SecretsApiKeyAuthenticator;
use esn\components\secrets\SecretsApiKeys;
use esn\components\secrets\SecretsApiQuota;
use esn\core\config\ProjectConfig;
use esn\core\DeveloperException;
use esn\core\Functions;
use esn\core\http\Request;
use rg\injektor\attributes\Inject;
use rg\injektor\attributes\Service;

#[Service]
class SecretsApiKeyService
{
    private const string REFRESH_SIGNATURE_HEADER = 'X-Refresh-Signature';

    #[Inject]
    protected ProjectConfig $projectConfig;

    private ?string $resolvedKey = null;

    private ?int $authenticatedAccountId = null;

    public function extractPresentedKey(Request $request): ?string
    {
        $header = $request->getHeader('Authorization');
        if ($header === null || trim($header) === '') {
            return null;
        }

        if ($request->getHeader(self::REFRESH_SIGNATURE_HEADER) !== null) {
            return null;
        }

        if (preg_match('/^Bearer\s+(\S+)$/i', trim($header), $matches) !== 1) {
            return '';
        }

        return $matches[1];
    }

    public function authenticateRequest(Request $request): ?int
    {
        $presentedKey = $this->extractPresentedKey($request);
        if ($presentedKey === null) {
            return null;
        }

        if ($this->resolvedKey === $presentedKey) {
            return $this->authenticatedAccountId;
        }

        $this->resolvedKey = $presentedKey;
        $this->authenticatedAccountId = null;

        $authenticator = $this->getAuthenticator();
        if ($authenticator === null || $presentedKey === '') {
            return null;
        }

        $this->authenticatedAccountId = $authenticator->authenticate($presentedKey);

        return $this->authenticatedAccountId;
    }

    public function getAuthenticatedAccountId(): ?int
    {
        return $this->authenticatedAccountId;
    }

    public function reserveRequestQuota(int $accountId): SecretsApiQuota
    {
        $authenticator = $this->getAuthenticator();
        if ($authenticator === null) {
            throw new DeveloperException('An API key was authenticated without an authenticator to reserve its quota');
        }

        return $authenticator->reserveRequestQuota($accountId);
    }

    private function getAuthenticator(): ?SecretsApiKeyAuthenticator
    {
        if (! $this->projectConfig instanceof SecretsApiKeys) {
            return null;
        }

        $authenticatorClass = $this->projectConfig->getSecretsApiKeyAuthenticatorClass();
        if ($authenticatorClass === null) {
            return null;
        }

        return Functions::getInstanceOfClass($authenticatorClass);
    }
}
