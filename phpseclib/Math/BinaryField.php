<?php

/**
 * Binary Finite Fields
 *
 * Utilizes the factory design pattern
 *
 * PHP version 8.1+
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2018-2026 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

declare(strict_types=1);

namespace phpseclib4\Math;

use phpseclib4\Common\Functions\Strings;
use phpseclib4\Exception\{ResourceLimitException, UnsupportedValueException};
use phpseclib4\Math\BinaryField\Integer;
use phpseclib4\Math\Common\FiniteField;

/**
 * Binary Finite Fields
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 * @psalm-api
 */
class BinaryField extends FiniteField
{
    /**
     * Instance Counter
     */
    private static int $instanceCounter = 0;

    /**
     * Keeps track of current instance
     */
    protected int $instanceID;

    private BigInteger $randomMax;

    /**
     * Reduction functions, shared by all fields with the same reduction polynomial
     *
     * @var array<string, \Closure>
     */
    private static array $reducers = [];

    /**
     * Default constructor
     */
    public function __construct(int ...$indices)
    {
        $m = array_shift($indices);
        if ($m > 571) {
            /* sect571r1 and sect571k1 are the largest binary curves that https://www.secg.org/sec2-v2.pdf defines
               altho theoretically there may be legit reasons to use binary finite fields with larger degrees
               imposing a limit on the maximum size is both reasonable and precedented. in particular,
               http://tools.ietf.org/html/rfc4253#section-6.1 (The Secure Shell (SSH) Transport Layer Protocol) says
               "implementations SHOULD check that the packet length is reasonable in order for the implementation to
                avoid denial of service and/or buffer overflow attacks" */
            throw new ResourceLimitException('Degrees larger than 571 are not supported');
        }
        // the other exponents index into a string of m + 1 characters: one past the end grows
        // the string to that length (2^63 bytes for an exponent from a key that saturates (int))
        if ($m < 1) {
            throw new UnsupportedValueException('The degree must be at least 1');
        }
        foreach ($indices as $index) {
            if ($index < 0 || $index >= $m) {
                throw new UnsupportedValueException('The exponents of the reduction polynomial must be between 0 and the degree');
            }
        }
        $val = str_repeat('0', $m) . '1';
        foreach ($indices as $index) {
            $val[$index] = '1';
        }
        $modulo = static::base2ToBase256(strrev($val));

        if (!isset(self::$reducers[$modulo])) {
            self::$reducers[$modulo] = self::reducer($m, rtrim(substr($val, 0, -1), '0'));
        }

        $this->instanceID = self::$instanceCounter++;
        Integer::setModulo($this->instanceID, $modulo);
        Integer::setRecurringModuloFunction($this->instanceID, self::$reducers[$modulo]);

        // the non-zero elements are 1 through 2^m - 1
        $this->randomMax = new BigInteger(str_repeat('1', $m), 2);
    }

    /**
     * Returns a function that reduces a polynomial modulo z^m + r(z)
     *
     * Implements algorithm 2.40 (in section 2.3.5) in "Guide to Elliptic Curve Cryptography" with W = 8.
     *
     * @param string $r the coefficients of r(z), lowest first
     */
    private static function reducer(int $m, string $r): \Closure
    {
        $t = (int) ceil($m / 8);
        // the length of the longest product of two field elements
        $pad = (int) ceil((2 * $m - 1) / 8);
        $finalMask = chr((1 << ($m % 8)) - 1);
        if ($finalMask == "\0") {
            $finalMask = "\xFF";
        }
        $topBits = ~ord($finalMask) & 0xFF;

        // $u[$k] is r(z) * z^k
        $u = [static::base2ToBase256(strrev($r))];
        for ($i = 1; $i < 8; $i++) {
            $u[] = static::base2ToBase256(strrev(str_repeat('0', $i) . $r));
        }

        // folding a whole byte at once only works if every bit it folds into lands below that byte
        [$table, $width] = $m >= strlen($r) + 7 ? self::foldTable($r, $m) : [null, 0];
        $q0 = $m >> 3;
        $partial = $m & 7;

        $fold = static function (string $c) use ($u, $m, $t, $finalMask, $pad, $table, $width, $q0, $partial): string {
            $length = max(strlen($c), $pad);
            if (isset($table)) {
                // bytes are numbered from the right, so byte $q holds the bits 8 * $q through 8 * $q + 7
                $c = str_pad($c, $length + $width, "\0", STR_PAD_LEFT);
                $last = $length + $width - 1;
                for ($q = $length - 1; $q >= $q0 && ($q > $q0 || !$partial); $q--) {
                    $v = ord($c[$last - $q]);
                    if ($v) {
                        $start = $length - ((8 * $q - $m) >> 3);
                        $c = substr_replace($c, substr($c, $start, $width) ^ $table[$v], $start, $width);
                    }
                }
                if ($partial) {
                    $v = ord($c[$last - $q0]);
                    for ($b = $partial; $b < 8; $b++) {
                        $temp = $u[$b - $partial];
                        if (($v >> $b) & 1 && strlen($temp)) {
                            $c = substr_replace($c, substr($c, -strlen($temp)) ^ $temp, -strlen($temp));
                        }
                    }
                }
            } else {
                // bit $i is bit $i & 7 of the byte $i >> 3 bytes from the right
                $c = str_pad($c, $length, "\0", STR_PAD_LEFT);
                for ($i = 8 * $length - 1; $i >= $m; $i--) {
                    if ((ord($c[$length - 1 - ($i >> 3)]) >> ($i & 7)) & 1) {
                        $temp = $u[($i - $m) & 7];
                        if (strlen($temp)) {
                            $start = $length - (($i - $m) >> 3) - strlen($temp);
                            $c = substr_replace($c, substr($c, $start, strlen($temp)) ^ $temp, $start, strlen($temp));
                        }
                    }
                }
            }
            $c = substr($c, -$t);
            if (strlen($c) == $t) {
                $c[0] = $c[0] & $finalMask;
            }
            return ltrim($c, "\0");
        };

        return static function (string $c) use ($fold, $t, $pad, $topBits): string {
            $c = ltrim($c, "\0");
            $length = strlen($c);
            if ($length < $t || ($length == $t && !(ord($c[0]) & $topBits))) {
                return $c;
            }
            if ($length <= $pad) {
                return $fold($c);
            }
            // each fold copies the whole string, so longer input is folded in 64-byte steps
            $i = $length % 64 ?: 64;
            $result = $fold(substr($c, 0, $i));
            for (; $i < $length; $i += 64) {
                $result = $fold($result . substr($c, $i, 64));
            }
            return $result;
        };
    }

    /**
     * Precomputes, for every byte value, what folding a byte of bits at or above z^m adds
     *
     * $r holds the coefficients of the reduction polynomial below z^m, lowest first. A byte that
     * starts at bit 8q contributes r(z) * z^(8q - m + b) for each bit b it has set, which is
     * table[byte] shifted left by (8q - m) >> 3 bytes, since the table includes the (8q - m) % 8 bit shift.
     *
     * @return array{0: list<string>, 1: int} the table and the length of its entries
     */
    private static function foldTable(string $r, int $m): array
    {
        $shift = (8 - $m % 8) % 8;
        $bits = [];
        for ($b = 0; $b < 8; $b++) {
            $bits[$b] = static::base2ToBase256(strrev(str_repeat('0', $shift + $b) . $r));
        }
        $width = max(array_map('strlen', $bits));
        foreach ($bits as $b => $value) {
            $bits[$b] = str_pad($value, $width, "\0", STR_PAD_LEFT);
        }
        $table = [str_repeat("\0", $width)];
        for ($v = 1; $v < 256; $v++) {
            $b = 0;
            while (!(($v >> $b) & 1)) {
                $b++;
            }
            $table[$v] = $table[$v & ($v - 1)] ^ $bits[$b];
        }
        return [$table, $width];
    }
    /**
     * Returns an instance of a dynamically generated PrimeFieldInteger class
     */
    public function newInteger(BigInteger|string $num): Integer
    {
        return new Integer($this->instanceID, $num instanceof BigInteger ? $num->toBytes() : $num);
    }

    /**
     * Returns a random non-zero element of the field
     */
    public function randomInteger(): Integer
    {
        static $one;
        if (!isset($one)) {
            $one = new BigInteger(1);
        }

        return new Integer($this->instanceID, BigInteger::randomRange($one, $this->randomMax)->toBytes());
    }

    /**
     * Returns the length of the modulo in bytes
     */
    public function getLengthInBytes(): int
    {
        return strlen(Integer::getModulo($this->instanceID));
    }

    /**
     * Returns the length of the modulo in bits
     */
    public function getLength(): int
    {
        return strlen(Integer::getModulo($this->instanceID)) << 3;
    }

    /**
     * Converts a base-2 string to a base-256 string
     */
    public static function base2ToBase256(string $x, ?int $size = null): string
    {
        $str = Strings::bits2bin($x);

        $pad = strlen($x) >> 3;
        if (strlen($x) & 3) {
            $pad++;
        }
        $str = str_pad($str, $pad, "\0", STR_PAD_LEFT);
        if (isset($size)) {
            $str = str_pad($str, $size, "\0", STR_PAD_LEFT);
        }

        return $str;
    }

    /**
     * Converts a base-256 string to a base-2 string
     */
    public static function base256ToBase2(string $x): string
    {
        if (function_exists('gmp_import')) {
            return gmp_strval(gmp_import($x), 2);
        }

        return Strings::bin2bits($x);
    }
}
