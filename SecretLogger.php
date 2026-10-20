<?php

declare(strict_types=1);

namespace esn\components\secrets;

use esn\core\Functions;
use esn\core\http\Request;
use rg\injektor\attributes\Inject;
use rg\injektor\attributes\Service;
use Throwable;
use esn\core\helper\StringHelper;

#[Service]
class SecretLogger
{
    private const string TOKEN_PATTERN = '#/[A-Za-z0-9_-]{22}(?=/|$)#';

    private const string BARE_TOKEN_PATTERN = '#(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{22}(?![A-Za-z0-9_-])#';

    private const string TOKEN_PLACEHOLDER = '/<token>';

    private const string BARE_TOKEN_PLACEHOLDER = '<token>';

    #[Inject]
    protected Request $request;

    public function logException(Throwable $e): void
    {
        $previous = $e->getPrevious();
        Functions::logError('secrets.exception', [
            'class' => $e::class,
            'message' => self::redact($e->getMessage()),
            'file' => $e->getFile() . ':' . $e->getLine(),
            'trace' => self::redact($e->getTraceAsString()),
            'previousClass' => $previous !== null ? $previous::class : null,
            'previousMessage' => $previous !== null ? self::redact($previous->getMessage()) : null,
            'path' => self::redact((string) $this->request->getBaseUrl()),
            'host' => gethostname(),
            'ipHash' => $this->clientIpHash(),
            'public' => true,
        ]);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function logWarning(string $message, array $context = []): void
    {
        Functions::logWarning($message, $this->sanitizeContext($context));
    }

    public static function redact(string $text): string
    {
        if ($text === '') {
            return $text;
        }
        $text = (string) preg_replace(self::TOKEN_PATTERN, self::TOKEN_PLACEHOLDER, $text);

        return (string) preg_replace(self::BARE_TOKEN_PATTERN, self::BARE_TOKEN_PLACEHOLDER, $text);
    }

    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    private function sanitizeContext(array $context): array
    {
        $context['public'] = true;
        if (!isset($context['ipHash'])) {
            $context['ipHash'] = $this->clientIpHash();
        }
        if (isset($context['path']) && StringHelper::isString($context['path'])) {
            $context['path'] = self::redact($context['path']);
        }
        return $context;
    }

    private function clientIpHash(): string
    {
        $ip = (string) $this->request->getClientIp();
        if ($ip === '') {
            return '';
        }
        return Functions::hashIp($ip);
    }
}
