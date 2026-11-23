<?php

/**
 * Binary Finite Fields
 *
 * Utilizes the factory design pattern
 *
 * PHP version 5 and 7
 *
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2017 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Math;

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Math\BinaryField\Integer;
use phpseclib3\Math\Common\FiniteField;

/**
 * Binary Finite Fields
 *
 * @author  Jim Wigginton <terrafrost@php.net>
 */
class BinaryField extends FiniteField
{
    /**
     * Instance Counter
     *
     * @var int
     */
    private static $instanceCounter = 0;

    /**
     * Keeps track of current instance
     *
     * @var int
     */
    protected $instanceID;

    /** @var BigInteger */
    private $randomMax;

    /**
     * Reduction functions, shared by all fields with the same reduction polynomial
     *
     * @var callable[]
     */
    private static $reducers = [];

    /**
     * Default constructor
     */
    public function __construct(...$indices)
    {
        $m = array_shift($indices);
        if ($m > 571) {
            /* sect571r1 and sect571k1 are the largest binary curves that https://www.secg.org/sec2-v2.pdf defines
               altho theoretically there may be legit reasons to use binary finite fields with larger degrees
               imposing a limit on the maximum size is both reasonable and precedented. in particular,
               http://tools.ietf.org/html/rfc4253#section-6.1 (The Secure Shell (SSH) Transport Layer Protocol) says
               "implementations SHOULD check that the packet length is reasonable in order for the implementation to
                avoid denial of service and/or buffer overflow attacks" */
            throw new \OutOfBoundsException('Degrees larger than 571 are not supported');
        }
        // the other exponents index into a string of m + 1 characters: one past the end grows
        // the string to that length (2^63 bytes for an exponent from a key that saturates (int))
        if ($m < 1) {
            throw new \InvalidArgumentException('The degree must be at least 1');
        }
        foreach ($indices as $index) {
            if ($index < 0 || $index >= $m) {
                throw new \InvalidArgumentException('The exponents of the reduction polynomial must be between 0 and the degree');
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

        $this->randomMax = new BigInteger($modulo, 2);
    }

    /**
     * Returns a function that reduces a polynomial modulo z^m + r(z)
     *
     * Implements algorithm 2.40 (in section 2.3.5) in "Guide to Elliptic Curve Cryptography" with W = 8.
     *
     * @param int $m
     * @param string $r the coefficients of r(z), lowest first
     * @return callable
     */
    private static function reducer($m, $r)
    {
        $t = (int) ceil($m / 8);
        // the length of the longest product of two field elements
        $pad = (int) ceil((2 * $m - 1) / 8);
        $finalMask = chr((1 << ($m % 8)) - 1);
        if ($finalMask == "\0") {
            $finalMask = "\xFF";
        }

        // $u[$k] is r(z) * z^k
        $u = [static::base2ToBase256(strrev($r))];
        for ($i = 1; $i < 8; $i++) {
            $u[] = static::base2ToBase256(strrev(str_repeat('0', $i) . $r));
        }

        $fold = static function ($c) use ($u, $m, $t, $finalMask, $pad) {
            $length = max(strlen($c), $pad);
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
            $c = substr($c, -$t);
            if (strlen($c) == $t) {
                $c[0] = $c[0] & $finalMask;
            }
            return ltrim($c, "\0");
        };

        return static function ($c) use ($fold, $pad) {
            $c = ltrim($c, "\0");
            $length = strlen($c);
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
     * Returns an instance of a dynamically generated PrimeFieldInteger class
     *
     * @param string $num
     * @return Integer
     */
    public function newInteger($num)
    {
        return new Integer($this->instanceID, $num instanceof BigInteger ? $num->toBytes() : $num);
    }

    /**
     * Returns an integer on the finite field between one and the prime modulo
     *
     * @return Integer
     */
    public function randomInteger()
    {
        static $one;
        if (!isset($one)) {
            $one = new BigInteger(1);
        }

        return new Integer($this->instanceID, BigInteger::randomRange($one, $this->randomMax)->toBytes());
    }

    /**
     * Returns the length of the modulo in bytes
     *
     * @return int
     */
    public function getLengthInBytes()
    {
        return strlen(Integer::getModulo($this->instanceID));
    }

    /**
     * Returns the length of the modulo in bits
     *
     * @return int
     */
    public function getLength()
    {
        return strlen(Integer::getModulo($this->instanceID)) << 3;
    }

    /**
     * Converts a base-2 string to a base-256 string
     *
     * @param string $x
     * @param int|null $size
     * @return string
     */
    public static function base2ToBase256($x, $size = null)
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
     *
     * @param string $x
     * @return string
     */
    public static function base256ToBase2($x)
    {
        if (function_exists('gmp_import')) {
            return gmp_strval(gmp_import($x), 2);
        }

        return Strings::bin2bits($x);
    }
}
