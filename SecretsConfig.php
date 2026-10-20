<?php

declare(strict_types=1);

namespace esn\components\secrets;

use esn\components\ComponentConfig;
use esn\core\config\ModuleConfig;

class SecretsConfig implements ModuleConfig, ComponentConfig
{
    public static function createConfig(): self
    {
        return new self();
    }

    public function getName(): string
    {
        return 'secrets';
    }

    public function getDatabaseSchemas(): array
    {
        return [
            'secrets',
        ];
    }

    public function getTwigFunctions(): array
    {
        return [];
    }

    public function getWidgets(): array
    {
        return [];
    }

    public function getTwigFilter(): array
    {
        return [];
    }

    public function getTwigData(): array
    {
        return [];
    }
}
