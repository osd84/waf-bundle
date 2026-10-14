<?php

namespace Osd84\WafBundle;

use Osd84\DiscordBundle\Discord;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Le pare-feu applicatif (repris de OsdAurox\Ban) : listes, bannissements, .htaccess.
 * Applique a chaque requete par Osd84\WafBundle\EventSubscriber\WafSubscriber.
 *
 * Tout est en fichiers texte, pas en base :
 *  - liste blanche (osd84_waf.whitelist_file) : jamais bloquee, jamais bannie ;
 *  - liste noire manuelle (osd84_waf.banlist_file) : versionnee, editee a la main, n'expire jamais ;
 *  - bannissements automatiques (<storage_dir>/bans.txt) : ecrits par le WAF, ils expirent au bout
 *    de ban_duration_days (une IP partagee ou reattribuee ne reste pas bannie pour toujours).
 * Une ligne = une IP ou une plage CIDR (192.0.2.0/24), "#" commence un commentaire.
 */
class Waf
{
    /** User-Agents de scanners : 404 sans bannir (le blocage tombe sur des pages ordinaires). Sous-chaine, sans casse. */
    public const USER_AGENTS = [
        'crusader-worker',
        'ProspectScope',
        'python-httpx',
        'python-requests',
        'AteveSearchSourceUrlDiscovery',
        'go-http-client',
        'libwww-perl',
        'Scrapy',
        // scanners de vulnerabilites / reconnaissance
        'sqlmap',
        'Nikto',
        'Nmap Scripting Engine',
        'masscan',
        'zgrab',
        'Nuclei',
        'wpscan',
        'dirbuster',
        'gobuster',
        'ffuf',
        'Acunetix',
        'Nessus',
        'OpenVAS',
        'CensysInspect',
        'Expanse',
    ];

    /** URL de scan, comparaison exacte avec le chemin (liste de OsdAurox\Ban::$blackListWords). */
    public const URL_EXACTES = [
        '/.git/config',
        '/wp-admin/admin-ajax.php',
        '/xmlrpc.php',
        '/.env',
        '/.git',
        '/idea',
        '/.idea',
        '/.env.local',
        '/config/.env',
        '/.env.production',
        '/.svn/entries',
        '/vendor/.env',
        '/docker-compose.yml',
        '/access.log',
        '/nginx.conf',
        '/cgit/config',
        '/apache2.conf',
        '/.kube/config',
        '/node_modules/package.json',
        '/.well-known/security.txt',
        '/.well-known/openid-configuration',
        '/.well-known/apple-app-site-association',
        '/api/v1/secrets',
        '/suitecrm/logfile.log',
        '/manager/html',
        '/zabbix/index.php',
        '/nagios/cgi-bin/status.cgi',
        '/.svn/text-base/index.php.svn-base',
        '/backend/.env',
        '/node_modules/.bin/',
        '/index.php.bak',
        '/.npmrc',
        '/config.old',
        '/phpinfo.php',
        '/.DS_Store',
        '/index.php.swp',
        '/config.php.swo',
        '/uploads',
        '/files',
        '/storage/logs/laravel.log',
        '/logs/access.log',
        '/logs/error.log',
        '/.editorconfig',
        '/.eslintrc',
        '/config.yml',
        '/database.yml',
        '/config.json',
        '/secrets.json',
        '/package.json',
        '/composer.json',
        '/composer.lock',
        '/.gitlab-ci.yml',
        '/.idea/workspace.xml',
        '/.bash_history',
        '/.vscode/settings.json',
        '/wp-content/debug.log',
        '/api/keys',
        '/debug/vars',
        '/env',
        '/.aws/credentials',
        '/.gcloud/credentials.json',
        '/wp-config.php',
        '/.svn/auth/',
        '/.git/objects',
        '/.bzr/branch/branch.conf',
        '/.hg/dirstate',
        '/.hg/hgrc',
        '/portal/.env',
        '/env/.env',
        '/api/.env',
        '/app/.env',
        '/dev/.env',
        '/new/.env',
        '/new/.env.local',
        '/new/.env.staging',
        '/_phpinfo.php',
        '/_profiler/phpinfo',
        '/_profiler/phpinfo/info.php',
        '/wp-config',
        '/aws-secret.yaml',
        '/awstats/.env',
        '/conf/.env',
        '/cron/.env',
        '/www/.env',
        '/env.backup',
        '/xampp/phpinfo.php',
        '/laravel/info.php',
        '/js/.env',
        '/laravel/.env',
        '/laravel/core/.env',
        '/mail/.env',
        '/mailer/.env',
        '/laravel/.env.local',
        '/laravel/core/.env.production',
        '/main/.env',
    ];

    /** Motifs de scan, sur l'URL brute (chemin + query) : un motif trouve = ban (liste de OsdAurox\Ban::$blackListPatterns). */
    public const URL_MOTIFS = [
        // dotfiles et gestionnaires de versions
        '~(^|/)\.(env|git|svn|hg|bzr|aws|kube|gcloud|idea|vscode|DS_Store|bash_history|npmrc|editorconfig|eslintrc)(\.|/|$)~i',
        '~\.env([./]|$)~i',
        // WordPress
        '~/wp-(login|admin|config|content/debug|signup|cron|trackback|comments-post)~i',
        '~/xmlrpc\.php~i',
        // phpinfo et equivalents
        '~/[a-z0-9_-]*phpinfo[a-z0-9_-]*\.php~i',
        '~/(info|php|pinfo|i|infos?|php-info|phpversion|old_phpinfo|linusadmin-phpinfo)\.php~i',
        '~/(test|temp|time|debug)\.php~i',
        // outils de debug des frameworks
        '~/_profiler/~i',
        '~/_environment~i',
        '~/webroot/~i',
        '~/(actuator|telescope|horizon|symfony/profiler)/~i',
        // sauvegardes et secrets
        '~/(config|database|settings|secrets|tokens|package|composer|sftp-config|deployment-config)\.(json|yml|yaml|old|bak|swp|swo|sql|zip|xml)$~i',
        '~/wp-config\.(php|txt)(\.(old|bak|save|swp))?$~i',
        '~\.(sql|sql\.gz|bak|backup|old|orig|save|swp|swo|zip|tar|tar\.gz|tgz|7z|rar|dump)$~i',
        '~/(www|site|backup|db|sql|public_html|web|admin|home|app|src)\.(zip|tar|tar\.gz|tgz|sql|sql\.gz|7z|rar)$~i',
        // outils d'administration
        '~/(manager/html|zabbix|nagios|phpmyadmin|pma|adminer|mysql)/~i',
        // arborescences sensibles
        '~/(node_modules|vendor)/~i',
        '~/(storage/logs|logs/(access|error)\.log|wp-content/debug\.log)~i',
        '~/\.well-known/(security\.txt|openid-configuration|apple-app-site-association)~i',
        '~/cgi-bin/~i',
        '~/(api/(keys|v1/secrets)|debug/vars)~i',
        '~/server-(status|info)~i',
        '~/(aws-secret|s3)\.ya?ml$~i',
        // exploits recurrents
        '~\$\{jndi:~i',
        '~%24%7Bjndi~i',
        '~/(boaform|setup\.cgi|hndUnblock\.cgi|cgi-bin/luci)~i',
        // inclusion de fichiers locaux
        '~/(etc/passwd|etc/shadow|proc/self/environ)~i',
    ];

    /** 404 que les navigateurs demandent tout seuls : jamais comptees dans la limite de 404. */
    public const NOT_FOUND_TOLEREES = '~^/(favicon\.ico|apple-touch-icon[^/]*\.png|browserconfig\.xml|site\.webmanifest)$~i';

    /** L'entretien (purge des bans expires, .htaccess a jour) passe au plus une fois par jour. */
    private const ENTRETIEN_DELAI_SECONDES = 86400;

    /** Le .htaccess n'est pas reecrit plus d'une fois par minute (un scan banni par rafales). */
    private const HTACCESS_DELAI_SECONDES = 60;

    /** Au-dela, les IP les plus anciennes restent bloquees par PHP seulement (Apache ralentit sur mutualise). */
    private const HTACCESS_MAX_IPS = 1000;

    /**
     * @param string[] $potsDeMiel  des URL qui n'existent pas dans l'appli et qu'aucun humain n'ouvre (/admin...) :
     *                              les visiter bannit. A choisir par appli, et a annoncer en Disallow dans robots.txt.
     * @param int $dureeBanJours    duree d'un ban automatique. Une ligne de bans.txt sans date (ajoutee a la main) n'expire pas.
     * @param Discord|null $discord alerte a chaque ban (null : osd84/discord-bundle non active)
     */
    public function __construct(
        private string $fichierListeBlanche,
        private string $fichierListeNoire,
        private string $dossierWaf,
        private bool $ecrireHtaccess,
        private string $fichierHtaccess,
        private string $appName,
        private array $potsDeMiel = [],
        private int $dureeBanJours = 30,
        private ?Discord $discord = null,
    ) {
    }

    public function dureeBanJours(): int
    {
        return $this->dureeBanJours;
    }

    // -------------------------------------------------------------------------
    // Les controles
    // -------------------------------------------------------------------------

    public function estListeBlanche(string $ip): bool
    {
        return IpUtils::checkIp($ip, $this->lireListe($this->fichierListeBlanche));
    }

    /** Bannie a la main (la liste noire manuelle) ou par le WAF depuis moins de DUREE_BAN_JOURS (<storage_dir>/bans.txt). */
    public function estBannie(string $ip): bool
    {
        if (IpUtils::checkIp($ip, $this->lireListe($this->fichierListeNoire))) {
            return true;
        }
        return IpUtils::checkIp($ip, $this->bansActifs());
    }

    public function userAgentInterdit(string $userAgent): bool
    {
        if ($userAgent === '') {
            return false;
        }
        foreach (self::USER_AGENTS as $morceau) {
            if (stripos($userAgent, $morceau) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Pourquoi cette URL bannit, ou null si elle est normale.
     * $chemin : le chemin seul (/admin) ; $uriBrute : chemin + query, non decodes.
     */
    public function motifDeBan(string $chemin, string $uriBrute): ?string
    {
        $cheminSansSlashFinal = $chemin !== '/' ? rtrim($chemin, '/') : $chemin;

        if (in_array($cheminSansSlashFinal, $this->potsDeMiel, true)) {
            return 'pot de miel ' . $chemin;
        }
        if (in_array($chemin, self::URL_EXACTES, true)) {
            return 'url de scan ' . $chemin;
        }
        foreach (self::URL_MOTIFS as $motif) {
            if (preg_match($motif, $uriBrute)) {
                return 'motif de scan ' . $motif . ' sur ' . $uriBrute;
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Bannir / debannir
    // -------------------------------------------------------------------------

    /**
     * Ajoute l'IP a <storage_dir>/bans.txt, recopie la liste dans le .htaccess (si active) et previent sur Discord.
     * Rend false si l'IP est invalide, en liste blanche ou deja bannie.
     */
    public function bannir(string $ip, string $motif): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP) || $this->estListeBlanche($ip) || $this->estBannie($ip)) {
            return false;
        }

        // le motif contient une URL tapee par l'attaquant : pas de retour a la ligne dans le fichier
        $motifPropre = (string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', mb_substr($motif, 0, 300));
        $ligne = $ip . "\t" . date('Y-m-d H:i:s') . "\t" . $motifPropre . "\n";

        if (!is_dir($this->dossierWaf)) {
            mkdir($this->dossierWaf, 0775, true);
        }
        file_put_contents($this->fichierBans(), $ligne, FILE_APPEND | LOCK_EX);

        $this->reconstruireHtaccessSiPerime();
        $this->discord?->send('[BAN] ' . $this->appName . ' : ' . $ip . ' (' . $motifPropre . ')');

        return true;
    }

    /** Retire l'IP des bannissements automatiques. Une IP de la liste noire manuelle se retire a la main. */
    public function debannir(string $ip): bool
    {
        if (!is_file($this->fichierBans())) {
            return false;
        }

        $garder = [];
        $trouvee = false;
        foreach (file($this->fichierBans(), FILE_IGNORE_NEW_LINES) as $ligne) {
            if (explode("\t", $ligne)[0] === $ip) {
                $trouvee = true;
                continue;
            }
            $garder[] = $ligne;
        }
        if (!$trouvee) {
            return false;
        }

        file_put_contents($this->fichierBans(), $garder ? implode("\n", $garder) . "\n" : '', LOCK_EX);
        $this->reconstruireHtaccess();
        return true;
    }

    /**
     * Retire de <storage_dir>/bans.txt les bans expires.
     *
     * @return int le nombre de lignes retirees
     */
    public function purgerBansExpires(): int
    {
        if (!is_file($this->fichierBans())) {
            return 0;
        }

        $garder = [];
        $retirees = 0;
        foreach (file($this->fichierBans(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $ligne) {
            if ($this->ligneExpiree($ligne)) {
                $retirees++;
                continue;
            }
            $garder[] = $ligne;
        }
        if ($retirees > 0) {
            file_put_contents($this->fichierBans(), $garder ? implode("\n", $garder) . "\n" : '', LOCK_EX);
        }
        return $retirees;
    }

    /**
     * Une fois par jour au plus (appele a chaque requete, ne coute qu'un stat de fichier) :
     * purge les bans expires et remet le .htaccess a jour. Sans cela, une IP expiree resterait
     * refusee par Apache tant qu'aucun nouveau ban ne reecrit le .htaccess.
     */
    public function entretienQuotidien(): void
    {
        $marqueur = $this->dossierWaf . '/entretien_dernier_passage';
        if (is_file($marqueur) && time() - (int) filemtime($marqueur) < self::ENTRETIEN_DELAI_SECONDES) {
            return;
        }
        if (!is_dir($this->dossierWaf)) {
            mkdir($this->dossierWaf, 0775, true);
        }
        touch($marqueur);

        $this->purgerBansExpires();
        $this->reconstruireHtaccess();
    }

    /** Date de fin d'un ban de bans.txt ("2026-11-12 21:00:00"), null s'il n'expire pas (ligne sans date). */
    public function finDuBan(string $ligne): ?string
    {
        $debut = $this->dateDuBan($ligne);
        return $debut ? $debut->modify('+' . $this->dureeBanJours . ' days')->format('Y-m-d H:i:s') : null;
    }

    /** @return string[] les lignes de <storage_dir>/bans.txt (ip, date, motif separes par des tabulations) */
    public function lignesBans(): array
    {
        if (!is_file($this->fichierBans())) {
            return [];
        }
        return file($this->fichierBans(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    }

    // -------------------------------------------------------------------------
    // .htaccess : Apache refuse les IP bannies avant meme de lancer PHP
    // -------------------------------------------------------------------------

    public function reconstruireHtaccessSiPerime(): void
    {
        $marqueur = $this->dossierWaf . '/htaccess_derniere_ecriture';
        if (is_file($marqueur) && time() - (int) filemtime($marqueur) < self::HTACCESS_DELAI_SECONDES) {
            return;
        }
        $this->reconstruireHtaccess();
    }

    /**
     * Reecrit le bloc "WAF_BAN" du .htaccess avec les IPv4 bannies (liste manuelle + automatique).
     * Les IPv6 restent bloquees par PHP seulement : certains Apache mutualises les comparent trop largement.
     * Rend false si l'ecriture du .htaccess est desactivee (osd84_waf.htaccess.enabled: false) ou impossible.
     */
    public function reconstruireHtaccess(): bool
    {
        if (!$this->ecrireHtaccess || !is_file($this->fichierHtaccess)) {
            return false;
        }
        if (!is_dir($this->dossierWaf)) {
            mkdir($this->dossierWaf, 0775, true);
        }
        touch($this->dossierWaf . '/htaccess_derniere_ecriture');

        $ips = [];
        foreach (array_merge($this->lireListe($this->fichierListeNoire), $this->bansActifs()) as $entree) {
            $ip = explode('/', $entree)[0];
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ips[] = $entree;
            }
        }
        $ips = array_values(array_unique($ips));
        if (count($ips) > self::HTACCESS_MAX_IPS) {
            $ips = array_slice($ips, -self::HTACCESS_MAX_IPS);
        }

        $bloc = '# === WAF_BAN_START === ' . count($ips) . ' IP - ' . date('c') . " (ecrit par Osd84\\WafBundle\\Waf, ne pas modifier)\n";
        if ($ips) {
            $bloc .= "<RequireAll>\n    Require all granted\n";
            foreach ($ips as $ip) {
                $bloc .= '    Require not ip ' . $ip . "\n";
            }
            $bloc .= "</RequireAll>\n";
        }
        $bloc .= "# === WAF_BAN_END ===\n";

        $actuel = file_get_contents($this->fichierHtaccess);
        if ($actuel === false) {
            return false;
        }
        $sansBloc = (string) preg_replace('/# === WAF_BAN_START ===.*?# === WAF_BAN_END ===\n?/s', '', $actuel);
        $nouveau = rtrim($sansBloc) . "\n\n" . $bloc;

        // ecriture dans un fichier voisin puis rename : Apache ne lit jamais un .htaccess a moitie ecrit
        $temporaire = $this->fichierHtaccess . '.tmp';
        if (file_put_contents($temporaire, $nouveau, LOCK_EX) === false) {
            return false;
        }
        return rename($temporaire, $this->fichierHtaccess);
    }

    // -------------------------------------------------------------------------

    private function fichierBans(): string
    {
        return $this->dossierWaf . '/bans.txt';
    }

    /**
     * Les IP de <storage_dir>/bans.txt dont le ban court encore.
     *
     * @return string[]
     */
    private function bansActifs(): array
    {
        if (!is_file($this->fichierBans())) {
            return [];
        }
        $ips = [];
        foreach (file($this->fichierBans(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $ligne) {
            if ($this->ligneExpiree($ligne)) {
                continue;
            }
            // premier mot : une ligne ajoutee a la main peut etre separee par des espaces
            $ip = (string) preg_split('/\s+/', trim($ligne))[0];
            if (filter_var(explode('/', $ip)[0], FILTER_VALIDATE_IP)) {
                $ips[] = $ip;
            }
        }
        return $ips;
    }

    /** Date de la ligne (2e colonne), null si elle n'en a pas de valide. */
    private function dateDuBan(string $ligne): ?\DateTimeImmutable
    {
        $date = explode("\t", $ligne)[1] ?? '';
        $debut = \DateTimeImmutable::createFromFormat('!Y-m-d H:i:s', trim($date));
        return $debut ?: null;
    }

    private function ligneExpiree(string $ligne): bool
    {
        $debut = $this->dateDuBan($ligne);
        return $debut !== null && $debut < new \DateTimeImmutable('-' . $this->dureeBanJours . ' days');
    }

    /**
     * Les entrees d'un fichier de liste : premier mot de chaque ligne, commentaires et lignes vides ignores.
     * Une entree qui n'est ni une IP ni une plage CIDR valide est ignoree.
     *
     * @return string[]
     */
    private function lireListe(string $fichier): array
    {
        if (!is_file($fichier)) {
            return [];
        }
        $entrees = [];
        foreach (file($fichier, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $ligne) {
            $ligne = trim((string) preg_replace('/#.*$/', '', $ligne));
            if ($ligne === '') {
                continue;
            }
            $entree = (string) preg_split('/\s+/', $ligne)[0];
            [$ip, $masque] = array_pad(explode('/', $entree, 2), 2, null);
            if (filter_var($ip, FILTER_VALIDATE_IP) && ($masque === null || ctype_digit($masque))) {
                $entrees[] = $entree;
            }
        }
        return $entrees;
    }
}
