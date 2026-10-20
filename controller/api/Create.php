<?php

declare(strict_types=1);

namespace esn\components\secrets\controller\api;

use DateInterval;
use DateTime;
use DateTimeZone;
use esn\components\secrets\Base64Url;
use esn\components\secrets\forms\SecretsValidators;
use esn\components\secrets\SecretLogger;
use esn\components\secrets\SecretsApiKeyAccessTrait;
use esn\components\secrets\SecretsHookDispatchTrait;
use esn\components\secrets\SecretsLimitsInterface;
use esn\components\secrets\services\SecretsApiKeyService;
use esn\components\secrets\services\SecretService;
use esn\core\helper\StringHelper;
use esn\core\http\ApiApplication;
use esn\core\http\FormValidation;
use esn\core\http\Http;
use esn\core\http\ProofOfWork;
use esn\core\http\ProofOfWorkConfig;
use esn\core\http\RateLimit;
use esn\core\http\RateLimitConfig;
use esn\core\http\Route;
use esn\core\security\CsrfExemptEndpoint;
use esn\core\security\PubliclyAccessibleEndpoint;
use InvalidArgumentException;
use rg\injektor\attributes\Inject;
use rg\injektor\attributes\Service;
use Throwable;

#[Service]
class Create extends ApiApplication implements FormValidation, ProofOfWork, RateLimit, PubliclyAccessibleEndpoint, CsrfExemptEndpoint
{
    use SecretsApiKeyAccessTrait;
    use SecretsHookDispatchTrait;

    #[Inject]
    protected SecretService $secretService;

    #[Inject]
    protected SecretLogger $secretLogger;

    #[Inject]
    protected SecretsApiKeyService $secretsApiKeyService;

    public function getRoutes(): array
    {
        return [
            new Route(Http::METHOD_POST, '/api/secrets'),
        ];
    }

    public function hasAccess(): bool
    {
        return true;
    }

    public function getRateLimit(): RateLimitConfig
    {
        return new RateLimitConfig(
            keyPrefix: 'secrets:create',
            perIpLimit: SecretService::RATE_LIMIT_WRITE_PER_MINUTE,
            globalLimit: SecretService::RATE_LIMIT_GLOBAL_WRITE_PER_MINUTE,
            windowSeconds: SecretService::RATE_LIMIT_WINDOW_SECONDS,
            recordOnlyOnSuccess: false,
        );
    }

    public function getProofOfWorkConfig(): ProofOfWorkConfig
    {
        return new ProofOfWorkConfig(
            difficulty: SecretService::POW_DIFFICULTY_BITS,
            windowSeconds: SecretService::POW_WINDOW_SECONDS,
        );
    }

    public function validate(): array
    {
        $apiKeyErrors = $this->validateApiKey();
        if ($apiKeyErrors !== []) {
            return $apiKeyErrors;
        }

        $body = $this->request->getRequest();
        $errors = [];

        $ciphertext = $body->get('ciphertext');
        if (! StringHelper::isString($ciphertext)) {
            $errors['ciphertext'] = 'Must be a string';
        } else {
            $ciphertextError = SecretsValidators::validateBase64($ciphertext, 1, SecretService::MAX_CIPHERTEXT_BYTES);
            if ($ciphertextError !== null) {
                $errors['ciphertext'] = $ciphertextError;
            }
        }

        $nonce = $body->get('nonce');
        if (! StringHelper::isString($nonce)) {
            $errors['nonce'] = 'Must be a string';
        } else {
            $nonceError = SecretsValidators::validateBase64Exact($nonce, SecretService::NONCE_LENGTH);
            if ($nonceError !== null) {
                $errors['nonce'] = $nonceError;
            }
        }

        $ttl = $body->get('ttl_seconds');
        $ttlError = SecretsValidators::validateTtl($ttl, $this->getMaxTtlSeconds());
        if ($ttlError !== null) {
            $errors['ttl_seconds'] = $ttlError;
        }

        $errors = array_merge($errors, SecretsValidators::validateAttachmentFields($body, $this->getMaxAttachmentBytes()));

        return $errors;
    }

    private function getMaxTtlSeconds(): int
    {
        if ($this->projectConfig instanceof SecretsLimitsInterface) {
            return $this->projectConfig->getMaxTtlSeconds();
        }

        return SecretService::DEFAULT_MAX_TTL_SECONDS;
    }

    private function getMaxAttachmentBytes(): int
    {
        if ($this->projectConfig instanceof SecretsLimitsInterface) {
            return $this->projectConfig->getMaxAttachmentBytes();
        }

        return SecretService::DEFAULT_MAX_ATTACHMENT_BYTES;
    }

    public function getData(): array
    {
        try {
            $quotaDenial = $this->reserveApiKeyQuota();
            if ($quotaDenial !== null) {
                return $quotaDenial;
            }

            $body = $this->request->getRequest();

            $ciphertext = Base64Url::decode((string) $body->get('ciphertext')) ?? '';
            $nonce = Base64Url::decode((string) $body->get('nonce')) ?? '';
            $ttl = (int) $body->get('ttl_seconds');

            $expiresAt = new DateTime('now', new DateTimeZone('UTC'));
            $expiresAt->add(new DateInterval('PT' . $ttl . 'S'));

            $attachmentCiphertextRaw = $body->get('attachment_ciphertext');
            $attachmentNonceRaw = $body->get('attachment_nonce');
            $attachmentMetaRaw = $body->get('attachment_meta');

            $attachmentCiphertext = StringHelper::isString($attachmentCiphertextRaw) ? Base64Url::decode($attachmentCiphertextRaw) : null;
            $attachmentNonce = StringHelper::isString($attachmentNonceRaw) ? Base64Url::decode($attachmentNonceRaw) : null;
            $attachmentMeta = StringHelper::isString($attachmentMetaRaw) ? Base64Url::decode($attachmentMetaRaw) : null;

            $secret = $this->secretService->createSecret(
                $ciphertext,
                $nonce,
                $expiresAt,
                $attachmentCiphertext,
                $attachmentNonce,
                $attachmentMeta,
                $this->getMaxAttachmentBytes(),
            );

            $this->notifySecretCreated($secret->getToken());

            return [
                'token' => $secret->getToken(),
                'expires_at' => $secret->getExpiresAt()->format(DATE_ATOM),
            ];
        } catch (InvalidArgumentException $e) {
            $this->httpStatusCode = Http::BAD_REQUEST;
            $this->secretLogger->logException($e);

            return $this->showErrorMessage('Invalid request');
        } catch (Throwable $e) {
            $this->secretLogger->logException($e);

            return $this->showErrorMessage('Unable to create secret');
        }
    }
}
