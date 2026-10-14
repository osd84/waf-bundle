# osd84/waf-bundle

Un petit pare-feu applicatif pour Symfony, en fichiers texte, sans base de données.
Repris du WAF de la librairie aurox (`OsdAurox\Ban`, `OsdAurox\IpInfo`).

*A small application firewall for Symfony, in plain text files: honeypots, scan URL patterns, scanner user agents, 404 bursts, GeoIP, IP bans with expiry, optional Apache `.htaccess` sync.*

## Ce qu'il fait

À chaque requête, avant le routeur et la sécurité (`kernel.request`, priorité 512) :

| Contrôle | Réponse | Bannit ? |
|---|---|---|
| IP en liste blanche | rien n'est contrôlé | jamais |
| User-Agent de scanner (`sqlmap`, `Nikto`, `python-requests`...) | 404 | non |
| IP bannie (liste manuelle, ou ban automatique pas encore expiré) | 403 | déjà |
| Pot de miel (URL que vous choisissez) | 403 | oui |
| URL ou motif de scan (`/.env`, `/wp-login.php`, `${jndi:`...) | 403 | oui |
| Pays non autorisé (GeoIP, si configuré) | 403 | non |
| Trop de pages 404 d'un visiteur non connecté (`kernel.exception`) | — | oui |

- Un ban automatique expire au bout de `ban_duration_days` (30 par défaut). La liste manuelle n'expire jamais.
- Une fois par jour (première requête), les bans expirés sont purgés et le `.htaccess` remis à jour.
- Une alerte Discord part à chaque ban si [osd84/discord-bundle](https://github.com/osd84/discord-bundle) est activé.
- L'IP est celle de `Request::getClientIp()`. Derrière un proxy ou un CDN, configurez `framework.trusted_proxies`,
  sinon toutes les IP vues sont celles du proxy.

## Installation

```bash
composer require osd84/waf-bundle
```

Sans Symfony Flex, déclarer les bundles dans `config/bundles.php` :

```php
Osd84\DiscordBundle\Osd84DiscordBundle::class => ['all' => true],   // facultatif : alertes Discord
Osd84\WafBundle\Osd84WafBundle::class => ['all' => true],
```

## Configuration

Toutes les clés, avec leur valeur par défaut :

```yaml
# config/packages/osd84_waf.yaml
osd84_waf:
    whitelist_file: '%kernel.project_dir%/config/waf/whitelist.txt'   # jamais bloquee, jamais bannie
    banlist_file: '%kernel.project_dir%/config/waf/banlist.txt'       # liste noire manuelle, n'expire jamais
    storage_dir: '%kernel.project_dir%/var/waf'                       # bans.txt + cache : a garder entre deux deploiements
    app_name: 'Symfony'                                               # dans les alertes et pour l'API GeoIP
    ban_message: 'Oops !'                                             # corps de la reponse 403
    ban_duration_days: 30
    honeypots: []                                                     # ex. ['/admin', '/backup'] : A CHOISIR PAR APPLI
    not_found:
        limit: 5                                                      # 5 pages 404 par minute, la 6e bannit
        interval: '1 minute'
    htaccess:
        enabled: false                                                # true : les IPv4 bannies vont dans le .htaccess
        file: '%kernel.project_dir%/public/.htaccess'
    geoip:
        api_url: ''                                                   # vide = desactive, aucune IP ne sort du serveur
        allowed_countries: []                                         # ex. ['FR'] ; vide = desactive
```

### Les listes

Une IP ou une plage CIDR par ligne, `#` pour commenter :

```
# config/waf/whitelist.txt
127.0.0.1
::1
203.0.113.7          # le bureau
```

- `whitelist_file` et `banlist_file` sont versionnés avec l'appli et édités à la main.
- `<storage_dir>/bans.txt` contient les bans automatiques : `IP<TAB>date<TAB>motif`. On peut le corriger à la main
  (supprimer une ligne débannit). Une ligne sans date n'expire pas.
- `storage_dir` ne doit être ni versionné ni effacé au déploiement.

### Les pots de miel

Des URL qui n'existent pas dans votre appli et qu'aucun humain n'ouvre. Les visiter bannit.

- **Choisissez les vôtres** : la liste par défaut est vide, parce qu'une liste publiée dans un dépôt public serait connue de tous les robots.
- Annoncez-les en `Disallow` dans `robots.txt` : un robot qui y cherche des chemins intéressants se fait bannir en les visitant.
- Attention : un humain qui tape `/admin` par réflexe est banni lui aussi. Mettez l'IP du bureau en liste blanche.
- **Aucune route de l'appli ne doit ressembler à un pot de miel** ni à un motif de `Waf::URL_MOTIFS`.

### GeoIP

`api_url` est appelée en `GET <api_url>?ip=1.2.3.4&src=<app_name>` et doit répondre
`{"datas": {"info": {"country_code": "FR"}}}` (le format de `OsdAurox\IpInfo`).

- L'API ne répond pas : on laisse passer, et on ne la redemande pas avant 5 minutes.
- Le pays d'une IP est gardé 30 jours dans `<storage_dir>/cache`.
- Le filtre s'applique à tout le site : un utilisateur en voyage est bloqué, sauf par la liste blanche.

### `.htaccess` (Apache)

Avec `htaccess.enabled: true`, les IPv4 bannies (liste manuelle et automatique, 1 000 au plus) sont recopiées
dans un bloc `WAF_BAN` du fichier, en `Require not ip`. Apache les refuse avant même de lancer PHP.

- Le reste du fichier est conservé ; l'écriture est atomique (fichier temporaire puis renommage).
- Les IPv6 restent bloquées par PHP : certains Apache mutualisés les comparent trop largement.
- Vérifiez une fois que l'hébergeur accepte `Require` dans un `.htaccess`, sinon tout le site tombe en erreur 500.
- Après un déploiement qui remet le `.htaccess` du dépôt : `php bin/console osd84:waf:htaccess`.

## Commandes

```bash
php bin/console osd84:waf:bans                      # bans automatiques, avec leur date de fin
php bin/console osd84:waf:ban 203.0.113.7 "motif"   # bannir a la main
php bin/console osd84:waf:unban 203.0.113.7         # debannir (la liste manuelle se modifie a la main)
php bin/console osd84:waf:ip 203.0.113.7            # liste blanche ? bannie ? pays ?
php bin/console osd84:waf:htaccess                  # recopier les bans dans le .htaccess
```

## Ce qui n'est pas repris d'aurox

- La réputation d'IP par AbuseIPDB.
- La détection de XSS / d'injection SQL par motifs : les requêtes préparées et l'échappement Twig font le vrai travail,
  et ces motifs donnent surtout des faux positifs.

## Tests

```bash
composer install
php vendor/bin/phpunit
```

## Licence

MIT.
