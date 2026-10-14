<?php

namespace Osd84\WafBundle\Command;

use Osd84\WafBundle\AbuseIp;
use Osd84\WafBundle\GeoIp;
use Osd84\WafBundle\Waf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Ce que le WAF pense d'une IP : liste blanche, bannie, pays, reputation (interroge les API si besoin).
 *   php bin/console osd84:waf:ip 203.0.113.7
 */
#[AsCommand(name: 'osd84:waf:ip', description: 'WAF : diagnostic d\'une IP')]
class WafIpCommand extends Command
{
    public function __construct(
        private Waf $waf,
        private GeoIp $geoIp,
        private AbuseIp $abuseIp,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('ip', InputArgument::REQUIRED, 'L\'IP a examiner');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $ip = (string) $input->getArgument('ip');
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $output->writeln('<error>IP invalide : ' . $ip . '</error>');
            return Command::FAILURE;
        }

        $output->writeln('Liste blanche : ' . ($this->waf->estListeBlanche($ip) ? 'oui' : 'non'));
        $output->writeln('Bannie        : ' . ($this->waf->estBannie($ip) ? 'oui' : 'non'));
        if ($this->geoIp->estActive()) {
            $pays = $this->geoIp->codePays($ip);
            $output->writeln('Pays          : ' . ($pays !== '' ? $pays : 'inconnu (API muette : laissee passer)'));
            $output->writeln('Pays autorise : ' . ($this->geoIp->paysAutorise($ip) ? 'oui' : 'non'));
        } else {
            $output->writeln('GeoIP         : desactivee (osd84_waf.geoip.api_url ou allowed_countries vide)');
        }
        if ($this->abuseIp->estActive()) {
            $score = $this->abuseIp->score($ip);
            $output->writeln('Score AbuseIP : ' . ($score !== null ? $score . ' / 100 (seuil ' . $this->abuseIp->seuil() . ')' : 'inconnu (API muette : laissee passer)'));
            $output->writeln('Reputation    : ' . ($this->abuseIp->estAbusive($ip) ? 'refusee' : 'acceptee'));
        } else {
            $output->writeln('AbuseIP       : desactivee (osd84_waf.abuseip.api_url vide)');
        }
        return Command::SUCCESS;
    }
}
