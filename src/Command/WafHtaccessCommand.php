<?php

namespace Osd84\WafBundle\Command;

use Osd84\WafBundle\Waf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Reecrit le bloc WAF_BAN du .htaccess (IPv4 de la liste manuelle et des bannissements).
 * A lancer apres un deploiement : l'envoi remet le .htaccess du depot, sans le bloc.
 * Ne fait rien si osd84_waf.htaccess.enabled vaut false.
 */
#[AsCommand(name: 'osd84:waf:htaccess', description: 'WAF : recopier les IP bannies dans le .htaccess')]
class WafHtaccessCommand extends Command
{
    public function __construct(
        private Waf $waf,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        if ($this->waf->reconstruireHtaccess()) {
            $output->writeln('.htaccess reecrit.');
        } else {
            $output->writeln('.htaccess non reecrit (osd84_waf.htaccess.enabled: false, ou fichier introuvable / non inscriptible).');
        }
        return Command::SUCCESS;
    }
}
