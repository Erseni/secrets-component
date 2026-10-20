<?php

declare(strict_types=1);

namespace esn\components\secrets\entities;

use Doctrine\ORM\Mapping\Column;
use Doctrine\ORM\Mapping\Entity;
use Doctrine\ORM\Mapping\Table;
use Doctrine\ORM\Mapping\UniqueConstraint;
use esn\core\database\DatabaseEntity;

#[Table(name: 'secrets.secret_stats')]
#[UniqueConstraint(name: 'secret_stats_metric_uq', columns: ['metric'])]
#[Entity]
class SecretStat extends DatabaseEntity
{
    public const string METRIC_SECRETS_SENT = 'secrets_sent';

    public const string METRIC_REQUESTS_CREATED = 'requests_created';

    #[Column(type: 'string', length: 64)]
    protected string $metric = '';

    #[Column(type: 'bigint')]
    protected string $count = '0';

    public function getMetric(): string
    {
        return $this->metric;
    }

    public function setMetric(string $metric): void
    {
        $this->metric = $metric;
    }

    public function getCount(): int
    {
        return (int) $this->count;
    }

    public function setCount(int $count): void
    {
        $this->count = (string) $count;
    }
}
