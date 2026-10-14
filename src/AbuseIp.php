<?php

namespace Osd84\WafBundle;

use Psr\Log\LoggerInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Reputation d'une IP (score AbuseIPDB de 0 a 100), par la meme API que OsdAurox\AbuseIp (osd84_waf.abuseip.api_url) :
 *   GET <osd84_waf.abuseip.api_url>?ip=1.2.3.4&src=<APP_NAME>
 *   ->  {"status": true, "datas": {"info": {"abuseConfidenceScore": 87, ...}}}
 *
 * - api_url vide : verification desactivee, aucune IP ne sort du serveur, tout le monde passe.
 * - Score >= threshold (50 par defaut, comme aurox) : 403, sans bannir (le score d'une IP bouge).
 * - L'API ne repond pas : on laisse passer (fail-open), et on ne la redemande pas avant 5 minutes.
 * - Le score d'une IP est garde 7 jours dans le cache du WAF (<storage_dir>/cache) ; aurox le gardait dans la table ip_abuse_cache.
 */
class AbuseIp
{
    private const DUREE_CACHE_SCORE = 7 * 24 * 3600;
    private const DUREE_CACHE_ECHEC = 300;
    private const TIMEOUT_SECONDES = 3;

    /** dans le cache : l'API n'a pas su repondre */
    private const SCORE_INCONNU = -1;

    public function __construct(
        private string $apiUrl,
        private int $seuil,
        private string $appName,
        private CacheInterface $cacheWaf,
        private ?LoggerInterface $logger = null,
    ) {
    }

    public function estActive(): bool
    {
        return $this->apiUrl !== '';
    }

    public function seuil(): int
    {
        return $this->seuil;
    }

    /** true si le score de l'IP atteint le seuil. Score inconnu : false (fail-open). */
    public function estAbusive(string $ip): bool
    {
        if (!$this->estActive()) {
            return false;
        }
        $score = $this->score($ip);
        return $score !== null && $score >= $this->seuil;
    }

    /** Score de 0 a 100, null si l'API ne sait pas ou ne repond pas. */
    public function score(string $ip): ?int
    {
        if ($this->apiUrl === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }

        $score = $this->cacheWaf->get('abuseip_' . md5($ip), function (ItemInterface $item) use ($ip): int {
            $score = $this->demanderALApi($ip);
            $item->expiresAfter($score === self::SCORE_INCONNU ? self::DUREE_CACHE_ECHEC : self::DUREE_CACHE_SCORE);
            return $score;
        });

        return $score === self::SCORE_INCONNU ? null : $score;
    }

    private function demanderALApi(string $ip): int
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
            $this->logger?->warning('AbuseIp : l\'API ne repond pas (IP {ip}, code HTTP {code})', ['ip' => $ip, 'code' => $codeHttp]);
            return self::SCORE_INCONNU;
        }

        $donnees = json_decode($reponse, true);
        if (!is_array($donnees) || ($donnees['status'] ?? false) !== true) {
            $this->logger?->warning('AbuseIp : reponse invalide de l\'API (IP {ip})', ['ip' => $ip]);
            return self::SCORE_INCONNU;
        }

        // les deux noms de champ que OsdAurox\AbuseIp accepte
        $score = $donnees['datas']['info']['abuseConfidenceScore'] ?? $donnees['datas']['info']['score'] ?? null;
        if (!is_numeric($score)) {
            return self::SCORE_INCONNU;
        }
        return max(0, min(100, (int) $score));
    }
}
