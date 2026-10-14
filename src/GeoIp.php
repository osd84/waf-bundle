<?php

namespace Osd84\WafBundle;

use Psr\Log\LoggerInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Pays d'une IP, par la meme API que OsdAurox\IpInfo (osd84_waf.geoip.api_url) :
 *   GET <osd84_waf.geoip.api_url>?ip=1.2.3.4&src=<APP_NAME>  ->  {"datas": {"info": {"country_code": "FR", ...}}}
 *
 * - api_url vide : geolocalisation desactivee, aucune IP ne sort du serveur, tout le monde passe.
 * - allowed_countries : les pays autorises (['FR'] ou ['FR', 'BE', 'CH']) ; liste vide = desactivee.
 * - L'API ne repond pas : on laisse passer (fail-open), et on ne la redemande pas avant 5 minutes.
 * - Le pays d'une IP est garde 30 jours dans le cache du WAF (<storage_dir>/cache, garde entre deux deploiements).
 */
class GeoIp
{
    private const DUREE_CACHE_PAYS = 30 * 24 * 3600;
    private const DUREE_CACHE_ECHEC = 300;
    private const TIMEOUT_SECONDES = 3;

    public function __construct(
        private string $apiUrl,
        /** @var string[] */
        private array $paysAutorises,
        private string $appName,
        private CacheInterface $cacheWaf,
        private ?LoggerInterface $logger = null,
    ) {
    }

    public function estActive(): bool
    {
        return $this->apiUrl !== '' && $this->listePays() !== [];
    }

    /** true si le pays de l'IP est autorise, ou si on ne le connait pas (fail-open). */
    public function paysAutorise(string $ip): bool
    {
        if (!$this->estActive()) {
            return true;
        }
        $pays = $this->codePays($ip);
        if ($pays === '') {
            return true;
        }
        return in_array($pays, $this->listePays(), true);
    }

    /** Code pays ISO ("FR"), '' si l'API ne sait pas ou ne repond pas. */
    public function codePays(string $ip): string
    {
        if ($this->apiUrl === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return '';
        }

        return $this->cacheWaf->get('geoip_' . md5($ip), function (ItemInterface $item) use ($ip): string {
            $pays = $this->demanderALApi($ip);
            $item->expiresAfter($pays === '' ? self::DUREE_CACHE_ECHEC : self::DUREE_CACHE_PAYS);
            return $pays;
        });
    }

    private function demanderALApi(string $ip): string
    {
        $url = $this->apiUrl . '?ip=' . urlencode($ip) . '&src=' . urlencode($this->appName);

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, self::TIMEOUT_SECONDES);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, 'osd84-waf-bundle');
        $reponse = curl_exec($ch);
        $codeHttp = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($codeHttp !== 200 || !is_string($reponse)) {
            $this->logger?->warning('GeoIp : l\'API ne repond pas (IP {ip}, code HTTP {code})', ['ip' => $ip, 'code' => $codeHttp]);
            return '';
        }

        $donnees = json_decode($reponse, true);
        $pays = $donnees['datas']['info']['country_code'] ?? '';
        return is_string($pays) && preg_match('/^[A-Z]{2}$/', strtoupper($pays)) ? strtoupper($pays) : '';
    }

    /** @return string[] ['FR', 'be'] -> ['FR', 'BE'] */
    private function listePays(): array
    {
        $pays = [];
        foreach ($this->paysAutorises as $code) {
            $code = strtoupper(trim((string) $code));
            if ($code !== '') {
                $pays[] = $code;
            }
        }
        return $pays;
    }
}
