<?php
// Fausse API OsdAurox\AbuseIp pour les tests, servie par "php -S" : le score depend de l'IP demandee.
header('Content-Type: application/json');
$scores = [
    '203.0.113.100' => 87,   // abusive
    '203.0.113.101' => 49,   // juste sous le seuil
    '203.0.113.102' => 50,   // pile le seuil
];
$ip = (string) ($_GET['ip'] ?? '');
if ($ip === '203.0.113.103') {
    echo json_encode(['status' => false, 'errors' => ['quota depasse']]);
    return;
}
if ($ip === '203.0.113.104') {
    http_response_code(500);
    return;
}
if (($_GET['src'] ?? '') !== 'Test') {
    http_response_code(400);
    return;
}
echo json_encode(['status' => true, 'datas' => ['info' => ['abuseConfidenceScore' => $scores[$ip] ?? 0, 'countryCode' => 'FR']]]);
