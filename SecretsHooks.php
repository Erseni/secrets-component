<?php

declare(strict_types=1);

namespace esn\components\secrets;

interface SecretsHooks
{
    /**
     * @return class-string<SecretsHooksListener>|null
     */
    public function getSecretsHooksClass(): ?string;
}
