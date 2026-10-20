<?php

declare(strict_types=1);

namespace esn\components\secrets;

interface SecretsHooksListener
{
    public function onSecretCreated(string $token): void;

    public function onRequestCreated(string $token): void;

    public function onStatusChanged(string $token, string $status): void;

    public function onSecretExpiredUnretrieved(string $token): void;

    public function onSecretPurged(string $token): void;

    public function onCleanupCompleted(): void;
}
