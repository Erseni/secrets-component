<?php

declare(strict_types=1);

namespace esn\components\secrets\controller\api;

use esn\components\secrets\Base64Url;
use esn\components\secrets\forms\SecretsValidators;
use esn\components\secrets\SecretLogger;
use esn\components\secrets\SecretsHookDispatchTrait;
use esn\components\secrets\services\SecretService;
use esn\core\http\ApiApplication;
use esn\core\http\FormValidation;
use esn\core\http\Http;
use esn\core\http\RateLimit;
use esn\core\http\RateLimitConfig;
use esn\core\http\Route;
use InvalidArgumentException;
use rg\injektor\attributes\Inject;
use rg\injektor\attributes\Service;
use Throwable;
use esn\core\helper\StringHelper;
use esn\components\secrets\entities\SecretRequest;
use esn\core\security\PubliclyAccessibleEndpoint;

#[Service]
class Fulfill extends ApiApplication implements FormValidation, RateLimit, PubliclyAccessibleEndpoint
{
    use SecretsHookDispatchTrait;

    #[Inject]
    protected SecretService $secretService;

    #[Inject]
    protected SecretLogger $secretLogger;

    private ?SecretRequest $secretRequest = null;

    private bool $secretRequestLoaded = false;

    public function getRoutes(): array
    {
        return [
            new Route(Http::METHOD_POST, '/api/secrets/requests/{token:[A-Za-z0-9_-]{22}}/fulfill'),
        ];
    }

    public function hasAccess(): bool
    {
        return true;
    }

    public function getRateLimit(): RateLimitConfig
    {
        return new RateLimitConfig(
            keyPrefix: 'secrets:fulfill',
            perIpLimit: SecretService::RATE_LIMIT_WRITE_PER_MINUTE,
            globalLimit: SecretService::RATE_LIMIT_GLOBAL_WRITE_PER_MINUTE,
            windowSeconds: SecretService::RATE_LIMIT_WINDOW_SECONDS,
            recordOnlyOnSuccess: false,
        );
    }

    public function validate(): array
    {
        $body = $this->request->getRequest();
        $errors = [];

        $fillerPub = $body->get('filler_pub');
        if (! StringHelper::isString($fillerPub)) {
            $errors['filler_pub'] = 'Must be a string';
        } else {
            $fillerPubError = SecretsValidators::validateBase64Exact($fillerPub, SecretService::PUBKEY_LENGTH);
            if ($fillerPubError !== null) {
                $errors['filler_pub'] = $fillerPubError;
            }
        }

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

        $maxAttachmentBytes = $this->getMaxAttachmentBytes();
        if ($maxAttachmentBytes !== null) {
            $errors = array_merge($errors, SecretsValidators::validateAttachmentFields($body, $maxAttachmentBytes));
        }

        return $errors;
    }

    private function getMaxAttachmentBytes(): ?int
    {
        return $this->loadSecretRequest()?->getMaxAttachmentBytes();
    }

    private function loadSecretRequest(): ?SecretRequest
    {
        if (! $this->secretRequestLoaded) {
            $this->secretRequest = $this->secretService->getRequest((string) $this->request->getPathParam('token'));
            $this->secretRequestLoaded = true;
        }

        return $this->secretRequest;
    }

    public function getData(): array
    {
        try {
            $token = (string) $this->request->getPathParam('token');
            $body = $this->request->getRequest();

            $fillerPub = Base64Url::decode((string) $body->get('filler_pub')) ?? '';
            $ciphertext = Base64Url::decode((string) $body->get('ciphertext')) ?? '';
            $nonce = Base64Url::decode((string) $body->get('nonce')) ?? '';

            $attachmentCiphertextRaw = $body->get('attachment_ciphertext');
            $attachmentNonceRaw = $body->get('attachment_nonce');
            $attachmentMetaRaw = $body->get('attachment_meta');

            $attachmentCiphertext = StringHelper::isString($attachmentCiphertextRaw) ? Base64Url::decode($attachmentCiphertextRaw) : null;
            $attachmentNonce = StringHelper::isString($attachmentNonceRaw) ? Base64Url::decode($attachmentNonceRaw) : null;
            $attachmentMeta = StringHelper::isString($attachmentMetaRaw) ? Base64Url::decode($attachmentMetaRaw) : null;

            $success = $this->secretService->fulfillRequest(
                $token,
                $fillerPub,
                $ciphertext,
                $nonce,
                $attachmentCiphertext,
                $attachmentNonce,
                $attachmentMeta,
                $this->getMaxAttachmentBytes() ?? 0,
            );

            if (! $success) {
                $this->httpStatusCode = Http::NOT_FOUND;

                return $this->showErrorMessage('Unable to fulfill request');
            }

            $this->notifyStatusChanged($token, SecretService::STATUS_FULFILLED);

            return [
                'fulfilled' => true,
            ];
        } catch (InvalidArgumentException $e) {
            $this->httpStatusCode = Http::BAD_REQUEST;
            $this->secretLogger->logException($e);

            return $this->showErrorMessage('Invalid request');
        } catch (Throwable $e) {
            $this->secretLogger->logException($e);

            return $this->showErrorMessage('Unable to fulfill request');
        }
    }
}
