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
class CreateRequest extends ApiApplication implements FormValidation, ProofOfWork, RateLimit, PubliclyAccessibleEndpoint, CsrfExemptEndpoint
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
            new Route(Http::METHOD_POST, '/api/secrets/requests'),
        ];
    }

    public function hasAccess(): bool
    {
        return true;
    }

    public function getRateLimit(): RateLimitConfig
    {
        return new RateLimitConfig(
            keyPrefix: 'secrets:create-request',
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

        $requesterPub = $body->get('requester_pub');
        if (! StringHelper::isString($requesterPub)) {
            $errors['requester_pub'] = 'Must be a string';
        } else {
            $pubError = SecretsValidators::validateBase64Exact($requesterPub, SecretService::PUBKEY_LENGTH);
            if ($pubError !== null) {
                $errors['requester_pub'] = $pubError;
            }
        }

        $ttl = $body->get('ttl_seconds');
        $ttlError = SecretsValidators::validateTtl($ttl, $this->getMaxTtlSeconds());
        if ($ttlError !== null) {
            $errors['ttl_seconds'] = $ttlError;
        }

        $attachmentsAllowedError = SecretsValidators::validateBoolean($body->get('attachments_allowed'));
        if ($attachmentsAllowedError !== null) {
            $errors['attachments_allowed'] = $attachmentsAllowedError;
        }

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

    private function resolveRequestMaxAttachmentBytes(): int
    {
        $body = $this->request->getRequest();
        if (! SecretsValidators::isTruthyBoolean($body->get('attachments_allowed'))) {
            return 0;
        }

        return max(0, $this->getMaxAttachmentBytes());
    }

    public function getData(): array
    {
        try {
            $body = $this->request->getRequest();

            $requesterPub = Base64Url::decode((string) $body->get('requester_pub')) ?? '';
            $ttl = (int) $body->get('ttl_seconds');

            $expiresAt = new DateTime('now', new DateTimeZone('UTC'));
            $expiresAt->add(new DateInterval('PT' . $ttl . 'S'));

            $quotaDenial = $this->reserveApiKeyQuota();
            if ($quotaDenial !== null) {
                return $quotaDenial;
            }

            $maxAttachmentBytes = $this->resolveRequestMaxAttachmentBytes();

            $request = $this->secretService->createRequest($requesterPub, $expiresAt, $maxAttachmentBytes);

            $this->notifyRequestCreated($request->getToken());

            return [
                'token' => $request->getToken(),
                'expires_at' => $request->getExpiresAt()->format(DATE_ATOM),
                'max_attachment_bytes' => $request->getMaxAttachmentBytes(),
            ];
        } catch (InvalidArgumentException $e) {
            $this->httpStatusCode = Http::BAD_REQUEST;
            $this->secretLogger->logException($e);

            return $this->showErrorMessage('Invalid request');
        } catch (Throwable $e) {
            $this->secretLogger->logException($e);

            return $this->showErrorMessage('Unable to create secret request');
        }
    }
}
