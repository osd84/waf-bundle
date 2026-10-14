<?php

namespace Osd84\WafBundle;

use Osd84\DiscordBundle\Discord;
use Osd84\WafBundle\Command\WafBanCommand;
use Osd84\WafBundle\Command\WafBansCommand;
use Osd84\WafBundle\Command\WafHtaccessCommand;
use Osd84\WafBundle\Command\WafIpCommand;
use Osd84\WafBundle\Command\WafUnbanCommand;
use Osd84\WafBundle\EventSubscriber\WafSubscriber;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\CacheStorage;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * Le WAF (repris de OsdAurox\Ban et OsdAurox\IpInfo), configure dans config/packages/osd84_waf.yaml.
 * Voir README.md pour la configuration complete.
 */
class Osd84WafBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->scalarNode('whitelist_file')
                    ->info('Liste blanche : jamais bloquee, jamais bannie (une IP ou plage CIDR par ligne)')
                    ->defaultValue('%kernel.project_dir%/config/waf/whitelist.txt')
                ->end()
                ->scalarNode('banlist_file')
                    ->info('Liste noire manuelle, versionnee : refusee partout, n\'expire jamais')
                    ->defaultValue('%kernel.project_dir%/config/waf/banlist.txt')
                ->end()
                ->scalarNode('storage_dir')
                    ->info('Bans automatiques (bans.txt) et cache (pays des IP, compteur de 404) : a garder entre deux deploiements')
                    ->defaultValue('%kernel.project_dir%/var/waf')
                ->end()
                ->scalarNode('app_name')
                    ->info('Nom de l\'appli dans les alertes Discord et pour l\'API GeoIP')
                    ->defaultValue('Symfony')
                ->end()
                ->scalarNode('ban_message')
                    ->info('Corps de la reponse 403')
                    ->defaultValue('Oops !')
                ->end()
                ->integerNode('ban_duration_days')
                    ->info('Duree d\'un ban automatique')
                    ->defaultValue(30)
                    ->min(1)
                ->end()
                ->arrayNode('honeypots')
                    ->info('Pots de miel : URL inexistantes qu\'aucun humain n\'ouvre (/admin...). Les visiter bannit. A choisir par appli.')
                    ->scalarPrototype()->end()
                    ->defaultValue([])
                ->end()
                ->arrayNode('not_found')
                    ->info('Rafales de 404 d\'un visiteur non connecte : au-dela de "limit" par "interval", l\'IP est bannie')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->integerNode('limit')->defaultValue(5)->min(1)->end()
                        ->scalarNode('interval')->defaultValue('1 minute')->end()
                    ->end()
                ->end()
                ->arrayNode('htaccess')
                    ->info('Recopier les IPv4 bannies dans un bloc du .htaccess (Apache les refuse avant PHP)')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')->defaultFalse()->end()
                        ->scalarNode('file')->defaultValue('%kernel.project_dir%/public/.htaccess')->end()
                    ->end()
                ->end()
                ->arrayNode('geoip')
                    ->info('Pays autorises : API de OsdAurox\IpInfo (?ip=...&src=... -> datas.info.country_code). Vide = desactive.')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('api_url')->defaultValue('')->end()
                        ->arrayNode('allowed_countries')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                        ->end()
                    ->end()
                ->end()
            ->end();
    }

    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $services = $container->services();

        // cache fichier dans storage_dir : il survit a un vidage de var/cache (deploiement)
        $services->set('osd84_waf.cache', FilesystemAdapter::class)
            ->args(['osd84_waf', 0, $config['storage_dir'] . '/cache']);

        $services->set('osd84_waf.not_found_limiter', RateLimiterFactory::class)
            ->args([
                [
                    'id'       => 'osd84_waf_not_found',
                    'policy'   => 'fixed_window',
                    'limit'    => $config['not_found']['limit'],
                    'interval' => $config['not_found']['interval'],
                ],
                service('osd84_waf.not_found_storage'),
            ]);
        $services->set('osd84_waf.not_found_storage', CacheStorage::class)
            ->args([service('osd84_waf.cache')]);

        $services->set(Waf::class)
            ->args([
                '$fichierListeBlanche' => $config['whitelist_file'],
                '$fichierListeNoire'   => $config['banlist_file'],
                '$dossierWaf'          => $config['storage_dir'],
                '$ecrireHtaccess'      => $config['htaccess']['enabled'],
                '$fichierHtaccess'     => $config['htaccess']['file'],
                '$appName'             => $config['app_name'],
                '$potsDeMiel'          => $config['honeypots'],
                '$dureeBanJours'       => $config['ban_duration_days'],
                // facultatif : sans osd84/discord-bundle active, pas d'alerte
                '$discord'             => service(Discord::class)->nullOnInvalid(),
            ]);

        $services->set(GeoIp::class)
            ->args([
                '$apiUrl'        => $config['geoip']['api_url'],
                '$paysAutorises' => $config['geoip']['allowed_countries'],
                '$appName'       => $config['app_name'],
                '$cacheWaf'      => service('osd84_waf.cache'),
                '$logger'        => service('logger')->nullOnInvalid(),
            ]);

        $services->set(WafSubscriber::class)
            ->args([
                '$waf'             => service(Waf::class),
                '$geoIp'           => service(GeoIp::class),
                '$notFoundLimiter' => service('osd84_waf.not_found_limiter'),
                '$messageBan'      => $config['ban_message'],
                // facultatif : sans la securite Symfony, on ne sait pas qui est connecte
                '$tokenStorage'    => service('security.token_storage')->nullOnInvalid(),
            ])
            ->tag('kernel.event_subscriber');

        $services->set(WafBanCommand::class)->args([service(Waf::class)])
            ->tag('console.command', ['command' => 'osd84:waf:ban', 'description' => 'WAF : bannir une IP']);
        $services->set(WafUnbanCommand::class)->args([service(Waf::class)])
            ->tag('console.command', ['command' => 'osd84:waf:unban', 'description' => 'WAF : debannir une IP']);
        $services->set(WafBansCommand::class)->args([service(Waf::class)])
            ->tag('console.command', ['command' => 'osd84:waf:bans', 'description' => 'WAF : lister les IP bannies automatiquement']);
        $services->set(WafHtaccessCommand::class)->args([service(Waf::class)])
            ->tag('console.command', ['command' => 'osd84:waf:htaccess', 'description' => 'WAF : recopier les IP bannies dans le .htaccess']);
        $services->set(WafIpCommand::class)->args([service(Waf::class), service(GeoIp::class)])
            ->tag('console.command', ['command' => 'osd84:waf:ip', 'description' => 'WAF : diagnostic d\'une IP']);
    }
}
