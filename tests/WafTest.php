<?php

namespace Osd84\WafBundle\Tests;

use Osd84\WafBundle\Waf;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpFoundation\Request;

/**
 * Le WAF de bout en bout, sur un noyau minimal. Les requetes viennent d'adresses de
 * documentation (203.0.113.x, 198.51.100.x) ; 127.0.0.1 est en liste blanche.
 */
class WafTest extends TestCase
{
    private string $dossier;
    private ?TestKernel $kernel = null;

    protected function setUp(): void
    {
        $this->dossier = sys_get_temp_dir() . '/osd84_waf_test_' . bin2hex(random_bytes(4));
        mkdir($this->dossier, 0775, true);
        file_put_contents($this->dossier . '/whitelist.txt', "127.0.0.1\n::1\n");
        file_put_contents($this->dossier . '/banlist.txt', "# vide\n");
    }

    protected function tearDown(): void
    {
        $this->kernel?->shutdown();
        (new Filesystem())->remove($this->dossier);
    }

    private function kernel(array $config = []): TestKernel
    {
        $this->kernel?->shutdown();
        $this->kernel = new TestKernel($this->dossier, $config);
        $this->kernel->boot();
        return $this->kernel;
    }

    private function get(string $uri, string $ip, array $entetes = []): int
    {
        $kernel = $this->kernel ?? $this->kernel();
        $requete = Request::create($uri, 'GET', [], [], [], array_merge(['REMOTE_ADDR' => $ip], $entetes));
        return $kernel->handle($requete)->getStatusCode();
    }

    private function bans(): string
    {
        return is_file($this->dossier . '/bans.txt') ? (string) file_get_contents($this->dossier . '/bans.txt') : '';
    }

    public function testPotDeMielBannitPuisBloqueTout(): void
    {
        $this->assertSame(200, $this->get('/page', '203.0.113.10'));

        $this->assertSame(403, $this->get('/admin', '203.0.113.10'));
        $this->assertStringContainsString("203.0.113.10\t", $this->bans());
        $this->assertStringContainsString('pot de miel /admin', $this->bans());

        $this->assertSame(403, $this->get('/page', '203.0.113.10'), 'bannie : plus rien ne passe');
        $this->assertSame(200, $this->get('/page', '203.0.113.11'), 'les autres passent');
        $this->assertSame(404, $this->get('/admin', '127.0.0.1'), 'la liste blanche n\'est jamais bannie');
        $this->assertSame(200, $this->get('/admin_appli', '203.0.113.12'), '/admin_appli n\'est pas le pot de miel /admin');
    }

    public function testSansPotsDeMielConfiguresRienNeBannit(): void
    {
        $this->kernel(['honeypots' => []]);
        $this->assertSame(404, $this->get('/admin', '203.0.113.13'));
        $this->assertSame('', $this->bans());
    }

    public function testUrlsEtMotifsDeScan(): void
    {
        $this->assertSame(403, $this->get('/.env', '203.0.113.20'));
        $this->assertSame(403, $this->get('/vieux/site/.env.local', '203.0.113.21'));
        $this->assertSame(403, $this->get('/wp-login.php', '203.0.113.22'));
        $this->assertSame(403, $this->get('/page?q=${jndi:ldap://x.example/a}', '203.0.113.23'));
        foreach (['203.0.113.20', '203.0.113.21', '203.0.113.22', '203.0.113.23'] as $ip) {
            $this->assertStringContainsString($ip . "\t", $this->bans());
        }
    }

    public function testUserAgentDeScanner404SansBan(): void
    {
        $this->assertSame(404, $this->get('/page', '203.0.113.30', ['HTTP_USER_AGENT' => 'sqlmap/1.7.2#stable']));
        $this->assertSame('', $this->bans());
        $this->assertSame(200, $this->get('/page', '203.0.113.30', ['HTTP_USER_AGENT' => 'Mozilla/5.0 Firefox/131.0']));
    }

    public function testRafaleDe404(): void
    {
        $this->kernel(['not_found' => ['limit' => 3, 'interval' => '1 minute']]);
        // les icones que les navigateurs demandent tout seuls ne comptent pas
        for ($i = 0; $i < 10; $i++) {
            $this->get('/apple-touch-icon-precomposed.png', '203.0.113.40');
        }
        $this->assertSame('', $this->bans());

        for ($i = 1; $i <= 3; $i++) {
            $this->assertSame(404, $this->get('/inconnue-' . $i, '203.0.113.40'));
        }
        $this->assertSame('', $this->bans());
        $this->get('/inconnue-4', '203.0.113.40');
        $this->assertStringContainsString("203.0.113.40\t", $this->bans());
        $this->assertSame(403, $this->get('/page', '203.0.113.40'));
    }

    public function testListeNoireManuelleAvecPlage(): void
    {
        file_put_contents($this->dossier . '/banlist.txt', "198.51.100.0/24   # hebergeur de robots\n");
        $this->assertSame(403, $this->get('/page', '198.51.100.77'));
        $this->assertSame(200, $this->get('/page', '198.51.101.1'));
    }

    public function testGeoIp(): void
    {
        $this->kernel(['geoip' => ['api_url' => 'http://127.0.0.1:9/geoip', 'allowed_countries' => ['FR']]]);

        // l'API ne repond pas : on laisse passer
        $this->assertSame(200, $this->get('/page', '203.0.113.50'));

        // pays deja connus (dans le cache du WAF)
        $cache = $this->kernel->getContainer()->get('test.cache');
        $cache->get('geoip_' . md5('203.0.113.51'), fn () => 'US');
        $cache->get('geoip_' . md5('203.0.113.52'), fn () => 'FR');

        $this->assertSame(403, $this->get('/page', '203.0.113.51'));
        $this->assertSame('', $this->bans(), 'un pays refuse ne bannit pas');
        $this->assertSame(200, $this->get('/page', '203.0.113.52'));
    }

    public function testAbuseIp(): void
    {
        // une fausse API sur un port libre, le temps du test
        $port = $this->portLibre();
        $serveur = proc_open(
            [PHP_BINARY, '-S', '127.0.0.1:' . $port, __DIR__ . '/Fixtures/fausse_api_abuseip.php'],
            [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $tuyaux
        );
        try {
            $this->attendrePort($port);
            $this->kernel(['abuseip' => ['api_url' => 'http://127.0.0.1:' . $port . '/', 'threshold' => 50]]);

            $this->assertSame(403, $this->get('/page', '203.0.113.100'), 'score 87 : refusee');
            $this->assertSame(200, $this->get('/page', '203.0.113.101'), 'score 49 : sous le seuil');
            $this->assertSame(403, $this->get('/page', '203.0.113.102'), 'score 50 : le seuil refuse');
            $this->assertSame(200, $this->get('/page', '203.0.113.103'), 'status false : laissee passer');
            $this->assertSame(200, $this->get('/page', '203.0.113.104'), 'API en erreur : laissee passer');
            $this->assertSame(200, $this->get('/page', '127.0.0.1'), 'liste blanche : jamais demandee');
            $this->assertSame('', $this->bans(), 'une mauvaise reputation ne bannit pas');

            $ip = new CommandTester((new Application($this->kernel))->find('osd84:waf:ip'));
            $ip->execute(['ip' => '203.0.113.100']);
            $this->assertStringContainsString('Score AbuseIP : 87 / 100 (seuil 50)', $ip->getDisplay());
            $this->assertStringContainsString('Reputation    : refusee', $ip->getDisplay());
        } finally {
            proc_terminate($serveur);
            proc_close($serveur);
        }

        // API coupee : le score reste en cache, l'echec aussi (pas de nouvel appel pendant 5 minutes)
        $this->assertSame(403, $this->get('/page', '203.0.113.100'));
        $this->assertSame(200, $this->get('/page', '203.0.113.104'));
    }

    public function testAbuseIpDesactiveeSansUrl(): void
    {
        $ip = new CommandTester((new Application($this->kernel()))->find('osd84:waf:ip'));
        $ip->execute(['ip' => '203.0.113.105']);
        $this->assertStringContainsString('AbuseIP       : desactivee', $ip->getDisplay());
        $this->assertSame(200, $this->get('/page', '203.0.113.105'));
    }

    private function portLibre(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        $port = (int) substr(strrchr(stream_socket_get_name($socket, false), ':'), 1);
        fclose($socket);
        return $port;
    }

    private function attendrePort(int $port): void
    {
        for ($i = 0; $i < 50; $i++) {
            $connexion = @fsockopen('127.0.0.1', $port, $codeErreur, $erreur, 0.1);
            if ($connexion) {
                fclose($connexion);
                return;
            }
            usleep(100000);
        }
        $this->fail('la fausse API ne demarre pas');
    }

    public function testMessageDeBanConfigurable(): void
    {
        $kernel = $this->kernel(['ban_message' => 'Acces refuse']);
        $reponse = $kernel->handle(Request::create('/admin', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.55']));
        $this->assertSame(403, $reponse->getStatusCode());
        $this->assertSame('Acces refuse', $reponse->getContent());
    }

    public function testCommandesBanUnban(): void
    {
        $application = new Application($this->kernel());

        $ban = new CommandTester($application->find('osd84:waf:ban'));
        $ban->execute(['ip' => '203.0.113.60', 'motif' => 'essai']);
        $this->assertStringContainsString('bannie', $ban->getDisplay());
        $this->assertSame(403, $this->get('/page', '203.0.113.60'));

        $ban->execute(['ip' => '127.0.0.1']);
        $this->assertSame(1, $ban->getStatusCode(), 'la liste blanche ne se bannit pas');

        $liste = new CommandTester($application->find('osd84:waf:bans'));
        $liste->execute([]);
        $this->assertStringContainsString('203.0.113.60', $liste->getDisplay());

        $unban = new CommandTester($application->find('osd84:waf:unban'));
        $unban->execute(['ip' => '203.0.113.60']);
        $this->assertStringContainsString('debannie', $unban->getDisplay());
        $this->assertSame(200, $this->get('/page', '203.0.113.60'));

        $ip = new CommandTester($application->find('osd84:waf:ip'));
        $ip->execute(['ip' => '127.0.0.1']);
        $this->assertStringContainsString('Liste blanche : oui', $ip->getDisplay());
    }

    public function testExpirationDesBansAutomatiques(): void
    {
        $this->kernel(['ban_duration_days' => 30]);
        $il_y_a_31_jours = date('Y-m-d H:i:s', strtotime('-31 days'));
        $il_y_a_29_jours = date('Y-m-d H:i:s', strtotime('-29 days'));
        file_put_contents($this->dossier . '/bans.txt',
            "203.0.113.80\t$il_y_a_31_jours\tvieux scan\n"
            . "203.0.113.81\t$il_y_a_29_jours\tscan recent\n"
            . "203.0.113.82   ajoutee a la main, sans date\n");
        file_put_contents($this->dossier . '/banlist.txt', "203.0.113.83\n");

        $this->assertSame(200, $this->get('/page', '203.0.113.80'), 'ban de plus de 30 jours : expire');
        $this->assertSame(403, $this->get('/page', '203.0.113.81'));
        $this->assertSame(403, $this->get('/page', '203.0.113.82'), 'ligne sans date : pas d\'expiration');
        $this->assertSame(403, $this->get('/page', '203.0.113.83'), 'la liste manuelle n\'expire jamais');

        // un ban expire peut etre repose
        $this->assertSame(403, $this->get('/admin', '203.0.113.80'));
        $this->assertSame(403, $this->get('/page', '203.0.113.80'));
    }

    private function wafAvecHtaccess(string $htaccess): Waf
    {
        return new Waf($this->dossier . '/whitelist.txt', $this->dossier . '/banlist.txt', $this->dossier, true, $htaccess, 'test', ['/admin'], 30);
    }

    public function testHtaccess(): void
    {
        $htaccess = $this->dossier . '/.htaccess';
        file_put_contents($htaccess, "RewriteEngine On\n");
        file_put_contents($this->dossier . '/banlist.txt', "198.51.100.0/24\n2001:db8::1\n");
        $waf = $this->wafAvecHtaccess($htaccess);

        $waf->bannir('203.0.113.70', 'essai');
        $this->assertTrue($waf->reconstruireHtaccess());
        $contenu = (string) file_get_contents($htaccess);
        $this->assertStringStartsWith("RewriteEngine On\n", $contenu, 'le reste du fichier est garde');
        $this->assertStringContainsString('Require not ip 198.51.100.0/24', $contenu);
        $this->assertStringContainsString('Require not ip 203.0.113.70', $contenu);
        $this->assertStringNotContainsString('2001:db8::1', $contenu, 'les IPv6 restent a PHP');

        $waf->debannir('203.0.113.70');
        $contenu = (string) file_get_contents($htaccess);
        $this->assertSame(1, substr_count($contenu, 'WAF_BAN_START'), 'le bloc est remplace, pas ajoute');
        $this->assertStringNotContainsString('203.0.113.70', $contenu);
    }

    public function testPurgeEtEntretienQuotidien(): void
    {
        $htaccess = $this->dossier . '/.htaccess';
        file_put_contents($htaccess, "RewriteEngine On\n");
        $il_y_a_40_jours = date('Y-m-d H:i:s', strtotime('-40 days'));
        file_put_contents($this->dossier . '/bans.txt',
            "203.0.113.90\t$il_y_a_40_jours\tvieux\n"
            . "203.0.113.91\t" . date('Y-m-d H:i:s') . "\trecent\n");
        $waf = $this->wafAvecHtaccess($htaccess);

        $waf->reconstruireHtaccess();
        $this->assertStringNotContainsString('203.0.113.90', (string) file_get_contents($htaccess));
        $this->assertStringContainsString('Require not ip 203.0.113.91', (string) file_get_contents($htaccess));

        $waf->entretienQuotidien();
        $this->assertStringNotContainsString('203.0.113.90', $this->bans());
        $this->assertStringContainsString('203.0.113.91', $this->bans());

        file_put_contents($this->dossier . '/bans.txt', "203.0.113.92\t$il_y_a_40_jours\tvieux\n", FILE_APPEND);
        $waf->entretienQuotidien();
        $this->assertStringContainsString('203.0.113.92', $this->bans(), 'deja passe aujourd\'hui');
        touch($this->dossier . '/entretien_dernier_passage', time() - 90000);
        $waf->entretienQuotidien();
        $this->assertStringNotContainsString('203.0.113.92', $this->bans());

        $this->assertSame('2026-10-31 10:00:00', $waf->finDuBan("203.0.113.93\t2026-10-01 10:00:00\tessai"));
        $this->assertNull($waf->finDuBan('203.0.113.94'));
    }
}
