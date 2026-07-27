<?php
/**
 * Cross-language parity test: runs the PHP Q_Crypto_OpenClaim_EVM helpers
 * and compares against the vectors produced by the JS implementation.
 * Run: php php_vectors.php
 */
require __DIR__ . '/keccak.php';
require __DIR__ . '/Crypto/OpenClaim/EVM.php';

$pass = 0; $fail = 0;
function check($n, $c, $d = '') {
    global $pass, $fail;
    if ($c) { $pass++; echo "  \xE2\x9C\x93 $n\n"; }
    else { $fail++; echo "  \xE2\x9C\x97 FAIL: $n" . ($d ? "  — $d" : '') . "\n"; }
}

// Vectors emitted by test-vectors.js (JS implementation)
$JS = [
  'salt'                 => '0x2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b',
  'url'                  => 'https://example.com/ocp-inbox',
  'endpointType:https'   => '0x185f9bba2cbb55ccc551bf477b28898af6285f41b66d7d6120c887ba9a9b24f9',
  'endpointType:webhook' => '0x91b90b2e32b45ee8848d5b820c9ddcc7d29a48fd6be938cf58d9f7bc97e272b1',
  'endpointType:p2p'     => '0xffc09f6e6daf49b56731b4c4e271528e169e01d1fd20d1304c11145574184d89',
  'commitment'           => '0xdf43c33148561934b47bb1d7a18fa08e39ca3cb1dbbbea6a7a716f6add4ea76b',
];

$C = 'Q_Crypto_OpenClaim_EVM';

echo "\xE2\x94\x80\xE2\x94\x80 endpointType: PHP vs JS \xE2\x94\x80\xE2\x94\x80\n";
foreach (['https','webhook','p2p'] as $p) {
    $php = $C::endpointType($p);
    $js  = $JS['endpointType:'.$p];
    echo "  $p\n    php: $php\n    js : $js\n";
    check("endpointType('$p') matches JS byte-for-byte", strtolower($php) === strtolower($js));
}
check('HTTPS === https (case-insensitive)',
    $C::endpointType('HTTPS') === $C::endpointType('https'));
check('different protocols do NOT collide',
    $C::endpointType('https') !== $C::endpointType('webhook'));

echo "\n\xE2\x94\x80\xE2\x94\x80 endpointCommitment: PHP vs JS \xE2\x94\x80\xE2\x94\x80\n";
$c = $C::endpointCommitment($JS['url'], $JS['salt']);
echo "    php: $c\n    js : {$JS['commitment']}\n";
check('endpointCommitment matches JS byte-for-byte',
    strtolower($c) === strtolower($JS['commitment']));
check('deterministic', $C::endpointCommitment($JS['url'], $JS['salt']) === $c);
check('different URL -> different commitment',
    $C::endpointCommitment('https://mallory.evil/inbox', $JS['salt']) !== $c);
check('different salt -> different commitment',
    $C::endpointCommitment($JS['url'], '0x' . str_repeat('3c', 32)) !== $c);
check('endpointVerify accepts the true (url,salt)',
    $C::endpointVerify($c, $JS['url'], $JS['salt']));
check('endpointVerify rejects a wrong url',
    !$C::endpointVerify($c, 'https://mallory.evil/inbox', $JS['salt']));

echo "\n\xE2\x94\x80\xE2\x94\x80 Salt is REQUIRED (privacy) \xE2\x94\x80\xE2\x94\x80\n";
$threw = false;
try { $C::endpointCommitment($JS['url'], ''); } catch (\Throwable $e) { $threw = true; }
check('empty salt rejected', $threw);
$threw = false;
try { $C::endpointCommitment($JS['url'], '0xdead'); } catch (\Throwable $e) { $threw = true; }
check('short salt rejected', $threw);
$threw = false;
try { $C::endpointType(''); } catch (\Throwable $e) { $threw = true; }
check('empty protocol rejected', $threw);

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
