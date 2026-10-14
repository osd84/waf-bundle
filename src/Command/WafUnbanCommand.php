<?php

namespace Osd84\WafBundle\Command;

use Osd84\WafBundle\Waf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Retire une IP des bannissements automatiques (<storage_dir>/bans.txt) et reecrit le .htaccess.
 *   php bin/console osd84:waf:unban 203.0.113.7
 * Une IP de la liste noire manuelle (osd84_waf.banlist_file) se retire a la main dans ce fichier.
 */
#[AsCommand(name: 'osd84:waf:unban', description: 'WAF : debannir une IP')]
class WafUnbanCommand extends Command
{
    public function __construct(
        private Waf $waf,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('ip', InputArgument::REQUIRED, 'L\'IP a debannir');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $ip = (string) $input->getArgument('ip');

        if ($this->waf->debannir($ip)) {
            $output->writeln($ip . ' debannie.');
        } else {
            $output->writeln($ip . ' n\'est pas dans <storage_dir>/bans.txt.');
        }

        // bannie quand meme : elle est dans la liste manuelle
        if ($this->waf->estBannie($ip)) {
            $output->writeln('<comment>' . $ip . ' reste bloquee par la liste noire manuelle (osd84_waf.banlist_file) : la retirer de ce fichier.</comment>');
        }
        return Command::SUCCESS;
    }
}
