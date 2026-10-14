<?php

namespace Osd84\WafBundle\Command;

use Osd84\WafBundle\Waf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Les bannissements automatiques (<storage_dir>/bans.txt), du plus ancien au plus recent, avec leur fin
 * (osd84_waf.ban_duration_days apres le ban). Une ligne expiree pas encore purgee apparait avec une fin passee.
 */
#[AsCommand(name: 'osd84:waf:bans', description: 'WAF : lister les IP bannies automatiquement')]
class WafBansCommand extends Command
{
    public function __construct(
        private Waf $waf,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $lignes = [];
        foreach ($this->waf->lignesBans() as $ligne) {
            [$ip, $date, $motif] = array_pad(explode("\t", $ligne, 3), 3, '');
            $lignes[] = [$ip, $date, $this->waf->finDuBan($ligne) ?? 'jamais', $motif];
        }

        if (!$lignes) {
            $output->writeln('Aucune IP bannie automatiquement.');
            return Command::SUCCESS;
        }

        $table = new Table($output);
        $table->setHeaders(['IP', 'Date', 'Fin du ban', 'Motif']);
        $table->setRows($lignes);
        $table->render();
        $output->writeln(count($lignes) . ' IP. La liste manuelle est dans la liste noire manuelle (osd84_waf.banlist_file).');
        return Command::SUCCESS;
    }
}
