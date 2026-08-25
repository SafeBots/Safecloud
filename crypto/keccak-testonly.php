<?php
/**
 * Minimal Keccak-256 (Ethereum variant, 0x01 padding) for test harness use.
 * Provides \Crypto\Keccak::hash($data, 256, $raw) which is what EVM.php calls.
 */
namespace Crypto;

class Keccak
{
    private static $RC = [
        '0000000000000001','0000000000008082','800000000000808a','8000000080008000',
        '000000000000808b','0000000080000001','8000000080008081','8000000000008009',
        '000000000000008a','0000000000000088','0000000080008009','000000008000000a',
        '000000008000808b','800000000000008b','8000000000008089','8000000000008003',
        '8000000000008002','8000000000000080','000000000000800a','800000008000000a',
        '8000000080008081','8000000000008080','0000000080000001','8000000080008008'
    ];
    private static $R = [
        [0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]
    ];

    private static function rotl64($x, $n) {
        $n %= 64; if ($n === 0) return $x;
        return (($x << $n) | (($x >> (64 - $n)) & ((1 << $n) - 1)));
    }

    private static function keccakF(&$A) {
        for ($round = 0; $round < 24; $round++) {
            $C = [];
            for ($x = 0; $x < 5; $x++) {
                $C[$x] = $A[$x][0] ^ $A[$x][1] ^ $A[$x][2] ^ $A[$x][3] ^ $A[$x][4];
            }
            $D = [];
            for ($x = 0; $x < 5; $x++) {
                $D[$x] = $C[($x + 4) % 5] ^ self::rotl64($C[($x + 1) % 5], 1);
            }
            for ($x = 0; $x < 5; $x++) for ($y = 0; $y < 5; $y++) $A[$x][$y] ^= $D[$x];

            $B = [];
            for ($x = 0; $x < 5; $x++) for ($y = 0; $y < 5; $y++) {
                $B[$y][(2 * $x + 3 * $y) % 5] = self::rotl64($A[$x][$y], self::$R[$x][$y]);
            }
            for ($x = 0; $x < 5; $x++) for ($y = 0; $y < 5; $y++) {
                $A[$x][$y] = $B[$x][$y] ^ ((~$B[($x + 1) % 5][$y]) & $B[($x + 2) % 5][$y]);
            }
            $A[0][0] ^= self::hexToInt(self::$RC[$round]);
        }
    }

    private static function hexToInt($hex) {
        // 64-bit from big-endian hex, as PHP signed int
        $hi = hexdec(substr($hex, 0, 8));
        $lo = hexdec(substr($hex, 8, 8));
        return (int)(($hi << 32) | $lo);
    }

    public static function hash($data, $bits = 256, $raw = false) {
        $rateBytes = (1600 - 2 * $bits) / 8;   // 136 for 256
        // Pad: 0x01 … 0x80 (Keccak, not SHA-3's 0x06)
        $len = strlen($data);
        $padLen = $rateBytes - ($len % $rateBytes);
        $padded = $data . chr(0x01) . str_repeat("\0", $padLen - 1);
        $padded[strlen($padded) - 1] = chr(ord($padded[strlen($padded) - 1]) | 0x80);

        $A = [];
        for ($x = 0; $x < 5; $x++) for ($y = 0; $y < 5; $y++) $A[$x][$y] = 0;

        $blocks = str_split($padded, $rateBytes);
        foreach ($blocks as $block) {
            for ($i = 0; $i < $rateBytes / 8; $i++) {
                $lane = substr($block, $i * 8, 8);
                // little-endian → int
                $v = 0;
                for ($b = 7; $b >= 0; $b--) { $v = ($v << 8) | ord($lane[$b]); }
                $x = $i % 5; $y = intdiv($i, 5);
                $A[$x][$y] ^= $v;
            }
            self::keccakF($A);
        }

        $out = '';
        $need = $bits / 8;
        $i = 0;
        while (strlen($out) < $need) {
            $x = $i % 5; $y = intdiv($i, 5);
            $v = $A[$x][$y];
            for ($b = 0; $b < 8; $b++) { $out .= chr(($v >> ($b * 8)) & 0xFF); }
            $i++;
        }
        $out = substr($out, 0, $need);
        return $raw ? $out : bin2hex($out);
    }
}
