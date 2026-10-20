<?php

declare(strict_types=1);

namespace esn\components\secrets;

interface SecretsApiKeys
{
    /**
     * @return class-string<SecretsApiKeyAuthenticator>|null
     */
    public function getSecretsApiKeyAuthenticatorClass(): ?string;
}
