<?php

namespace Osd84\WafBundle\Command;

use Osd84\WafBundle\Waf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Bannit une IP a la main (ajoutee a <storage_dir>/bans.txt, comme un ban automatique).
 *   php bin/console osd84:waf:ban 203.0.113.7 "scan du 12/10"
 * Pour un ban permanent et versionne (ou une plage CIDR) : la liste noire manuelle (osd84_waf.banlist_file).
 */
#[AsCommand(name: 'osd84:waf:ban', description: 'WAF : bannir une IP')]
class WafBanCommand extends Command
{
    public function __construct(
        private Waf $waf,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('ip', InputArgument::REQUIRED, 'L\'IP a bannir');
        $this->addArgument('motif', InputArgument::OPTIONAL, 'Pourquoi', 'ban manuel (console)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $ip = (string) $input->getArgument('ip');

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $output->writeln('<error>IP invalide : ' . $ip . '</error>');
            return Command::FAILURE;
        }
        if ($this->waf->estListeBlanche($ip)) {
            $output->writeln('<error>' . $ip . ' est en liste blanche (osd84_waf.whitelist_file) : pas de ban.</error>');
            return Command::FAILURE;
        }
        if (!$this->waf->bannir($ip, (string) $input->getArgument('motif'))) {
            $output->writeln($ip . ' est deja bannie.');
            return Command::SUCCESS;
        }

        $output->writeln($ip . ' bannie.');
        return Command::SUCCESS;
    }
}
