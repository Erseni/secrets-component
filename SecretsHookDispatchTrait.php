<?php

declare(strict_types=1);

namespace esn\components\secrets;

use esn\components\secrets\services\CleanupResult;
use esn\core\Functions;
use Throwable;

/**
 * @property \esn\core\config\ProjectConfig $projectConfig
 * @property SecretLogger $secretLogger
 */
trait SecretsHookDispatchTrait
{
    private function dispatchSecretsHook(callable $callback): void
    {
        if (! $this->projectConfig instanceof SecretsHooks) {
            return;
        }

        $hooksClass = $this->projectConfig->getSecretsHooksClass();
        if ($hooksClass === null) {
            return;
        }

        try {
            $hooks = Functions::getInstanceOfClass($hooksClass);

            $callback($hooks);
        } catch (Throwable $e) {
            $this->secretLogger->logException($e);
        }
    }

    private function notifySecretCreated(string $token): void
    {
        $this->dispatchSecretsHook(static fn(SecretsHooksListener $hooks) => $hooks->onSecretCreated($token));
    }

    private function notifyRequestCreated(string $token): void
    {
        $this->dispatchSecretsHook(static fn(SecretsHooksListener $hooks) => $hooks->onRequestCreated($token));
    }

    private function notifyStatusChanged(string $token, string $status): void
    {
        $this->dispatchSecretsHook(static fn(SecretsHooksListener $hooks) => $hooks->onStatusChanged($token, $status));
    }

    private function notifyCleanupCompleted(CleanupResult $result): void
    {
        $this->dispatchSecretsHook(static function (SecretsHooksListener $hooks) use ($result): void {
            foreach ($result->expiredSecretTokens as $token) {
                $hooks->onSecretExpiredUnretrieved($token);
            }

            foreach ($result->purgedTokens as $token) {
                $hooks->onSecretPurged($token);
            }

            $hooks->onCleanupCompleted();
        });
    }
}
