<?php

declare(strict_types=1);

namespace DurableWorkflow\Ci;

final class TrustRefused extends \RuntimeException {}

final class ComposerTrust
{
    public const FILE_VARIABLES = [
        'SSL_CERT_FILE', 'CURL_CA_BUNDLE', 'GIT_SSL_CAINFO', 'COMPOSER_CAFILE',
    ];

    public const OPTIONAL_FILE_VARIABLES = ['REQUESTS_CA_BUNDLE', 'PIP_CERT', 'NPM_CONFIG_CAFILE', 'CARGO_HTTP_CAINFO', 'CARGO_HTTP_PROXY_CAINFO'];

    public const DIRECTORY_VARIABLES = ['SSL_CERT_DIR', 'GIT_SSL_CAPATH', 'COMPOSER_CAPATH'];

    public static function requireVersion(string $version): void
    {
        if (!str_starts_with($version, '2.') || version_compare($version, '2.10.3', '<')) {
            throw new TrustRefused('Composer 2.10.3 or newer on the 2 line is required.');
        }
    }

    public static function inspectBundle(string $path): int
    {
        $contents = file_get_contents($path);
        if ($contents === false || !preg_match_all('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $contents, $certificates)) {
            throw new TrustRefused('The selected bundle must contain PEM certificates.');
        }
        foreach ($certificates[0] as $certificate) {
            $parsed = @openssl_x509_parse($certificate);
            if ($parsed === false) {
                throw new TrustRefused('Malformed certificate in the selected bundle.');
            }
            foreach ((array) ($parsed['subject']['CN'] ?? []) as $subject) {
                if (in_array($subject, ['AAA Certificate Services', 'emSign ECC Root CA - G3'], true)) {
                    throw new TrustRefused('Blocked certificate in the selected bundle: '.$subject);
                }
            }
        }
        return count($certificates[0]);
    }

    private static function selectedPath(array $variables, bool $isDirectory = false): string
    {
        $selected = '';
        foreach ($variables as $variable) {
            $value = getenv($variable);
            $path = $value === false || $value === '' ? false : realpath($value);
            if ($path === false || ($isDirectory ? !is_dir($path) : !is_file($path)) || ($selected !== '' && $selected !== $path)) {
                throw new TrustRefused('CI CA overrides must select the same regular file or empty directory: '.$variable);
            }
            if ($isDirectory && scandir($path) !== ['.', '..']) {
                throw new TrustRefused('Additional CA overrides must select the same empty directory: '.$variable);
            }
            $selected = $path;
        }
        return $selected;
    }

    private static function configuration(string $project): \Composer\Config
    {
        $project = realpath($project);
        if ($project === false || !is_dir($project)) {
            throw new TrustRefused('The Composer project directory must exist.');
        }
        $config = \Composer\Factory::createConfig(null, $project);
        $manifest = getenv('COMPOSER') ?: 'composer.json';
        if (str_contains($manifest, '://')) {
            throw new TrustRefused('Remote Composer configuration is not permitted.');
        }
        if (!str_starts_with($manifest, '/') && !preg_match('/^[A-Za-z]:[\\\\\/]/', $manifest)) {
            $manifest = $project.DIRECTORY_SEPARATOR.$manifest;
        }
        if (is_file($manifest)) {
            $data = json_decode((string) file_get_contents($manifest), true, flags: JSON_THROW_ON_ERROR);
            $config->merge(['config' => $data['config'] ?? []], 'project');
        }
        if ($config->get('disable-tls') || !$config->get('secure-http')) {
            throw new TrustRefused('Composer TLS and secure HTTP must remain enabled.');
        }
        return $config;
    }

    public static function verify(string $composer, string $project): array
    {
        \Phar::loadPhar($composer);
        require_once 'phar://composer.phar/vendor/autoload.php';
        $version = \Composer\Composer::VERSION;
        self::requireVersion($version);
        $variables = self::FILE_VARIABLES;
        foreach (self::OPTIONAL_FILE_VARIABLES as $variable) {
            if (getenv($variable) !== false) {
                $variables[] = $variable;
            }
        }
        $bundle = self::selectedPath($variables);
        $directory = self::selectedPath(self::DIRECTORY_VARIABLES, true);
        $expectedHash = getenv('DW_CI_CA_SHA256');
        $actualHash = hash_file('sha256', $bundle);
        if (!is_string($expectedHash) || !preg_match('/^[a-f0-9]{64}$/D', $expectedHash) || !hash_equals($expectedHash, $actualHash)) {
            throw new TrustRefused('The selected bundle differs from the authenticated CI bundle.');
        }
        $config = self::configuration($project);
        if (realpath($config->get('cafile')) !== $bundle || realpath($config->get('capath')) !== $directory) {
            throw new TrustRefused('Composer must select the authenticated bundle and empty additional-root directory.');
        }
        return [
            'composer_version' => $version,
            'ca_file' => $bundle,
            'ca_directory' => $directory,
            'sha256' => $actualHash,
            'certificates' => self::inspectBundle($bundle),
            'blocked_roots' => ['AAA Certificate Services' => 0, 'emSign ECC Root CA - G3' => 0],
        ];
    }
}

if (realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    try {
        echo json_encode(ComposerTrust::verify($argv[1] ?? '', $argv[2] ?? '.'), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES).PHP_EOL;
    } catch (\Throwable $error) {
        $message = $error instanceof TrustRefused ? $error->getMessage() : 'Composer trust inspection failed ('.$error::class.').';
        fwrite(STDERR, $message.PHP_EOL);
        if (getenv('GITHUB_ACTIONS') === 'true') {
            echo '::error title=Composer trust refusal::'.strtr($message, ['%' => '%25', "\r" => '%0D', "\n" => '%0A']).PHP_EOL;
        }
        exit(1);
    }
}
