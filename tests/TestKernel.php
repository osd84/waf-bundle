<?php

namespace Osd84\WafBundle\Tests;

use Osd84\WafBundle\Osd84WafBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/**
 * Un noyau minimal : une seule page (/page, 200), tout le reste en 404.
 * Le dossier du WAF (listes, bans, cache) est propre a chaque test.
 */
class TestKernel extends Kernel
{
    use MicroKernelTrait;

    public function __construct(private string $dossier, private array $configWaf = [])
    {
        parent::__construct('test', true);
    }

    public function registerBundles(): iterable
    {
        return [new FrameworkBundle(), new Osd84WafBundle()];
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            'test' => true,
            'secret' => 'test',
            'http_method_override' => false,
            'handle_all_throwables' => true,
            'php_errors' => ['log' => true],
            'router' => ['utf8' => true],
        ]);
        $container->extension('osd84_waf', array_merge([
            'whitelist_file' => $this->dossier . '/whitelist.txt',
            'banlist_file'   => $this->dossier . '/banlist.txt',
            'storage_dir'    => $this->dossier,
            'app_name'       => 'Test',
            'honeypots'      => ['/admin', '/backup'],
        ], $this->configWaf));

        // services prives rendus visibles aux tests
        $container->services()->alias('test.waf', \Osd84\WafBundle\Waf::class)->public();
        $container->services()->alias('test.cache', 'osd84_waf.cache')->public();
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('page', '/page')->controller('kernel::page');
        $routes->add('admin_appli', '/admin_appli')->controller('kernel::page');
    }

    public function page(): Response
    {
        return new Response('ok');
    }

    // un conteneur compile est une classe PHP : sans nom propre a chaque noyau,
    // les tests suivants reutiliseraient celui du premier (et ses chemins)
    protected function getContainerClass(): string
    {
        return parent::getContainerClass() . '_' . md5($this->dossier . serialize($this->configWaf));
    }

    public function getCacheDir(): string
    {
        return $this->dossier . '/kernel_cache';
    }

    public function getLogDir(): string
    {
        return $this->dossier . '/kernel_log';
    }
}
