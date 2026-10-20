<?php

declare(strict_types=1);

namespace esn\components\secrets\controller\api;

use DateTime;
use esn\components\cronjobs\Cronjob;
use esn\components\cronjobs\CronjobTrigger;
use esn\components\cronjobs\IntervalTrigger;
use esn\components\cronjobs\TimeIntervalTrigger;
use esn\components\secrets\SecretLogger;
use esn\components\secrets\SecretsHookDispatchTrait;
use esn\components\secrets\services\SecretService;
use esn\core\http\ApiApplication;
use esn\core\http\Http;
use esn\core\http\Route;
use rg\injektor\attributes\Inject;
use rg\injektor\attributes\Service;

#[Service]
class CleanupSecrets extends ApiApplication implements Cronjob
{
    use SecretsHookDispatchTrait;

    #[Inject]
    protected SecretService $secretService;

    #[Inject]
    protected SecretLogger $secretLogger;

    public function getRoutes(): array
    {
        return [
            new Route(Http::METHOD_GET, '/api/jobs/cleanup-secrets'),
            new Route(Http::METHOD_POST, '/api/jobs/cleanup-secrets'),
        ];
    }

    public function hasAccess(): bool
    {
        return $this->accessManager->hasInternalApiAccess();
    }

    public function getData(): array
    {
        $result = $this->secretService->cleanupExpired();
        $this->notifyCleanupCompleted($result);

        return [
            'deleted' => $result->deleted,
        ];
    }

    public function getApiUrl(): string
    {
        return '/api/jobs/cleanup-secrets';
    }

    public function getTrigger(): CronjobTrigger
    {
        $from = new DateTime();
        $from->setTime(3, 0, 0);
        $to = new DateTime();
        $to->setTime(3, 5, 0);

        return new CronjobTrigger([
            new TimeIntervalTrigger($from, $to),
            new IntervalTrigger(3600, self::class),
        ]);
    }

    public function isNoParallelCronjob(): bool
    {
        return true;
    }
}
