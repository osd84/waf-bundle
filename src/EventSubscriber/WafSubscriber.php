<?php

namespace Osd84\WafBundle\EventSubscriber;

use Osd84\WafBundle\AbuseIp;
use Osd84\WafBundle\GeoIp;
use Osd84\WafBundle\Waf;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * Le WAF, a chaque requete, avant le routeur et la securite (priorite 512), dans cet ordre :
 *   0. IP en liste blanche : rien n'est controle ;
 *   1. User-Agent de scanner : 404, sans bannir ;
 *   2. IP deja bannie (ban automatique pas encore expire, ou liste manuelle) : 403 ;
 *   3. pot de miel, URL ou motif de scan : l'IP est bannie, 403 ;
 *   4. pays non autorise (GeoIP) : 403, sans bannir ;
 *   5. mauvaise reputation (score AbuseIPDB >= osd84_waf.abuseip.threshold) : 403, sans bannir.
 * Et a chaque 404 d'un visiteur non connecte : au-dela de osd84_waf.not_found.limit par osd84_waf.not_found.interval, l'IP est bannie.
 *
 * L'IP est celle de Request::getClientIp() : REMOTE_ADDR, pas de X-Forwarded-For (pas de proxy de confiance).
 */
class WafSubscriber implements EventSubscriberInterface
{
    /**
     * @param TokenStorageInterface|null $tokenStorage pour reconnaitre un utilisateur connecte (null : pas de securite Symfony)
     */
    public function __construct(
        private Waf $waf,
        private GeoIp $geoIp,
        private AbuseIp $abuseIp,
        private RateLimiterFactory $notFoundLimiter,
        private string $messageBan = 'Oops !',
        private ?TokenStorageInterface $tokenStorage = null,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST   => ['controlerRequete', 512],
            KernelEvents::EXCEPTION => ['compterNotFound', 0],
        ];
    }

    public function controlerRequete(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        // une fois par jour : bans expires retires, .htaccess remis a jour
        $this->waf->entretienQuotidien();

        $request = $event->getRequest();
        $ip = (string) $request->getClientIp();

        // 0. liste blanche
        if ($ip === '' || $this->waf->estListeBlanche($ip)) {
            return;
        }

        // 1. User-Agent de scanner : 404 plutot que 403, rien d'exploitable pour l'operateur du robot
        if ($this->waf->userAgentInterdit((string) $request->headers->get('User-Agent', ''))) {
            $event->setResponse(new Response('Not Found', Response::HTTP_NOT_FOUND));
            return;
        }

        // 2. deja bannie
        if ($this->waf->estBannie($ip)) {
            $event->setResponse(new Response($this->messageBan, Response::HTTP_FORBIDDEN));
            return;
        }

        // 3. pot de miel, URL ou motif de scan
        $motif = $this->waf->motifDeBan($request->getPathInfo(), $request->getRequestUri());
        if ($motif !== null) {
            $this->waf->bannir($ip, $motif);
            $event->setResponse(new Response($this->messageBan, Response::HTTP_FORBIDDEN));
            return;
        }

        // 4. pays
        if (!$this->geoIp->paysAutorise($ip)) {
            $event->setResponse(new Response($this->messageBan, Response::HTTP_FORBIDDEN));
            return;
        }

        // 5. reputation : pas de ban, le score d'une IP baisse quand les signalements cessent
        if ($this->abuseIp->estAbusive($ip)) {
            $event->setResponse(new Response($this->messageBan, Response::HTTP_FORBIDDEN));
        }
    }

    /** Une rafale de 404 : aucun humain n'en fait autant, c'est un scan. */
    public function compterNotFound(ExceptionEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        $exception = $event->getThrowable();
        if (!$exception instanceof HttpExceptionInterface || $exception->getStatusCode() !== Response::HTTP_NOT_FOUND) {
            return;
        }

        $request = $event->getRequest();
        $ip = (string) $request->getClientIp();
        if ($ip === '' || $this->waf->estListeBlanche($ip)) {
            return;
        }
        // un utilisateur connecte qui ouvre une fiche supprimee n'est pas un scanner
        if ($this->tokenStorage?->getToken()?->getUser() !== null) {
            return;
        }
        // ce que les navigateurs demandent tout seuls (favicon, icones iOS)
        if (preg_match(Waf::NOT_FOUND_TOLEREES, $request->getPathInfo())) {
            return;
        }

        if (!$this->notFoundLimiter->create('not_found_' . $ip)->consume(1)->isAccepted()) {
            $this->waf->bannir($ip, 'rafale de 404, la derniere sur ' . $request->getRequestUri());
        }
    }
}
