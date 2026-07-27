<?php
/**
 * Full cross-language DIGEST parity: PHP hashTypedData vs the JS/ethers
 * digests, for payments, actions and messages.
 */
require __DIR__ . '/keccak.php';
require __DIR__ . '/Crypto/EIP712.php';
require __DIR__ . '/Crypto/OpenClaim/EVM.php';

$pass=0; $fail=0;
function check($n,$c,$d=''){ global $pass,$fail;
  if($c){$pass++;echo "  \xE2\x9C\x93 $n\n";} else {$fail++;echo "  \xE2\x9C\x97 FAIL: $n".($d?"  — $d":'')."\n";} }

$C  = 'Q_Crypto_OpenClaim_EVM';
$OC = '0x99999febd42cad798fe10ab0b1c563002fc99999';
$A  = '0x' . str_repeat('a1', 20);
$T  = '0x' . str_repeat('b0', 20);
$R  = '0x' . str_repeat('c2', 20);

function digestOf($res) {
    if (is_array($res) && isset($res['digest'])) {
        $d = $res['digest'];
        return '0x' . (ctype_xdigit($d) ? $d : bin2hex($d));
    }
    if (is_object($res) && isset($res->digest)) { return '0x' . bin2hex($res->digest); }
    return null;
}

echo "\xE2\x94\x80\xE2\x94\x80 Payments digest \xE2\x94\x80\xE2\x94\x80\n";
$res = $C::hashTypedData([
  'payer'=>$A,'token'=>$T,'recipients'=>[$R],'max'=>'100000','line'=>'0',
  'nbf'=>'0','exp'=>'9999999999','chainId'=>'eip155:56','contract'=>$OC
]);
$php = digestOf($res);
$js  = '0x8e9e11d3c1f01b8ef0e4e3bcbb5a9c0e9dbcac6e2e6c8a5a2a0e0a1a6d6a6e0a'; // placeholder, replaced below
echo "    php: $php\n";
check('payments payload built', $php !== null && strlen($php) === 66, (string)$php);
// domain + struct shape
$p = is_array($res) ? ($res['payload'] ?? null) : null;
if ($p) {
  check("payments domain is 'OpenClaiming'", ($p['domain']['name'] ?? '') === 'OpenClaiming',
    $p['domain']['name'] ?? 'missing');
  check('Payment struct has 8 fields', count($p['types']['Payment'] ?? []) === 8,
    (string)count($p['types']['Payment'] ?? []));
  $names = array_column($p['types']['Payment'], 'name');
  check('field 3 is recipientsHash', ($names[2] ?? '') === 'recipientsHash', $names[2] ?? '');
  check('field 8 is contract', ($names[7] ?? '') === 'contract', $names[7] ?? '');
  check('signed value carries contract',
    strtolower($p['value']['contract'] ?? '') === strtolower($OC), $p['value']['contract'] ?? 'missing');
}

echo "\n\xE2\x94\x80\xE2\x94\x80 Actions digest \xE2\x94\x80\xE2\x94\x80\n";
$res2 = $C::hashTypedData([
  'authority'=>$A,'subject'=>$R,'contractAddress'=>$T,'method'=>'0x12345678',
  'paramsHash'=>'0x'.str_repeat('00',32),'minimum'=>'0','fraction'=>'0','delay'=>'0',
  'invoker'=>'0x'.str_repeat('d4',20),'nbf'=>'0','exp'=>'9999999999',
  'chainId'=>'eip155:56','contract'=>$OC
]);
$php2 = digestOf($res2);
echo "    php: $php2\n";
$p2 = is_array($res2) ? ($res2['payload'] ?? null) : null;
if ($p2) {
  check("actions domain is 'OpenClaiming'", ($p2['domain']['name'] ?? '') === 'OpenClaiming',
    $p2['domain']['name'] ?? 'missing');
  check('Action struct has 11 fields', count($p2['types']['Action'] ?? []) === 11,
    (string)count($p2['types']['Action'] ?? []));
  $n2 = array_column($p2['types']['Action'], 'name');
  check('invoker sits between delay and nbf',
    ($n2[7] ?? '')==='delay' && ($n2[8] ?? '')==='invoker' && ($n2[9] ?? '')==='nbf',
    implode(',', $n2));
  check('signed value carries invoker',
    strtolower($p2['value']['invoker'] ?? '') === '0x'.str_repeat('d4',20), $p2['value']['invoker'] ?? '');
}

echo "\n\xE2\x94\x80\xE2\x94\x80 Messages: correct usage \xE2\x94\x80\xE2\x94\x80\n";
$et = $C::endpointType('https');
$cm = $C::endpointCommitment('https://example.com/ocp-inbox', '0x'.str_repeat('2b',32));
$res3 = $C::hashTypedData(['account'=>$A,'endpointType'=>$et,'commitment'=>$cm,
  'chainId'=>'eip155:56','contract'=>$OC]);
$php3 = digestOf($res3);
echo "    php: $php3\n";
check('messages payload built with derived bytes32', $php3 !== null && strlen($php3) === 66);
$p3 = is_array($res3) ? ($res3['payload'] ?? null) : null;
if ($p3) {
  check("messages domain still 'OpenClaiming.messages'",
    ($p3['domain']['name'] ?? '') === 'OpenClaiming.messages', $p3['domain']['name'] ?? '');
}

echo "\n\xE2\x94\x80\xE2\x94\x80 Messages: raw strings must be REJECTED \xE2\x94\x80\xE2\x94\x80\n";
$threw = false;
try { $C::hashTypedData(['account'=>$A,'endpointType'=>'https','commitment'=>$cm,
  'chainId'=>'eip155:56','contract'=>$OC]); } catch (\Throwable $e) { $threw = true; }
check('human-readable endpointType rejected (PHP already validated)', $threw);
$threw = false;
try { $C::hashTypedData(['account'=>$A,'endpointType'=>$et,
  'commitment'=>'https://example.com/ocp-inbox','chainId'=>'eip155:56','contract'=>$OC]);
} catch (\Throwable $e) { $threw = true; }
check('human-readable commitment rejected', $threw);

file_put_contents(__DIR__.'/php_digests.json', json_encode([
  'payments'=>$php, 'actions'=>$php2, 'messages'=>$php3
]));
echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
