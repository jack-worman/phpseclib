<?php

/**
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib3\Tests\Unit\Math;

use phpseclib3\Math\BinaryField;
use phpseclib3\Tests\PhpseclibTestCase;

class BinaryFieldTest extends PhpseclibTestCase
{
    public static function badBinaryFieldDegrees()
    {
        return [
            'exponent past the degree' => [[163, 200, 0]],
            'exponent far past the degree' => [[163, 1 << 40, 0]],
            'negative exponent' => [[163, -100000, 0]],
            'degree 0' => [[0, 0]],
            'negative degree' => [[-5, 1, 0]],
        ];
    }

    /**
     * An EC key with explicit characteristic-two parameters sets these from the key; an exponent
     * past the degree grew a string to that many bytes (an out-of-memory fatal error)
     */
    /** @dataProvider badBinaryFieldDegrees */
    public function testBinaryFieldDegreesAreChecked(array $degrees)
    {
        $this->expectException('InvalidArgumentException');
        new BinaryField(...$degrees);
    }

    public static function binaryFields()
    {
        return [
            'sect113' => [[113, 9, 0]],
            'sect131' => [[131, 8, 3, 2, 0]],
            'sect163' => [[163, 7, 6, 3, 0]],
            'sect193' => [[193, 15, 0]],
            'sect233' => [[233, 74, 0]],
            'sect239' => [[239, 158, 0]],
            'sect283' => [[283, 12, 7, 5, 0]],
            'sect409' => [[409, 87, 0]],
            'sect571' => [[571, 10, 5, 2, 0]],
            'degree a multiple of 8' => [[128, 7, 2, 1, 0]],
        ];
    }

    /** @dataProvider binaryFields */
    public function testArithmeticMatchesBitByBitReference(array $degrees)
    {
        $field = new BinaryField(...$degrees);
        $m = $degrees[0];
        $length = (int) ceil(($m + 1) / 8);
        for ($i = 0; $i < 5; $i++) {
            $a = self::pseudoRandomBytes((int) ceil($m / 8), "a$i");
            $b = self::pseudoRandomBytes((int) ceil($m / 8), "b$i");

            $x = self::reduce(self::toBits($a), $degrees);
            $y = self::reduce(self::toBits($b), $degrees);
            $product = self::reduce(self::multiply($x, $y), $degrees);
            $square = self::reduce(self::multiply($x, $x), $degrees);

            $a = $field->newInteger($a);
            $b = $field->newInteger($b);
            $this->assertSame(self::toHex($x, $length), $a->toHex());
            $this->assertSame(self::toHex($product, $length), $a->multiply($b)->toHex());
            $this->assertSame(self::toHex($square, $length), $a->multiply($a)->toHex());
        }
    }

    private static function pseudoRandomBytes($length, $seed)
    {
        $bytes = '';
        for ($i = 0; strlen($bytes) < $length; $i++) {
            $bytes .= hash('sha512', "$seed-$i", true);
        }
        return substr($bytes, 0, $length);
    }

    /**
     * @return int[] the bits of a big-endian string, lowest first
     */
    private static function toBits($bytes)
    {
        $bits = [];
        for ($i = strlen($bytes) - 1; $i >= 0; $i--) {
            for ($b = 0; $b < 8; $b++) {
                $bits[] = (ord($bytes[$i]) >> $b) & 1;
            }
        }
        return $bits;
    }

    private static function toHex(array $bits, $length)
    {
        $bytes = '';
        for ($i = 0; $i < $length; $i++) {
            $byte = 0;
            for ($b = 0; $b < 8; $b++) {
                if (!empty($bits[8 * $i + $b])) {
                    $byte |= 1 << $b;
                }
            }
            $bytes = chr($byte) . $bytes;
        }
        return bin2hex($bytes);
    }

    private static function multiply(array $x, array $y)
    {
        $z = array_fill(0, count($x) + count($y), 0);
        foreach ($x as $i => $xi) {
            if ($xi) {
                foreach ($y as $j => $yj) {
                    $z[$i + $j] ^= $yj;
                }
            }
        }
        return $z;
    }

    private static function reduce(array $bits, array $degrees)
    {
        $m = array_shift($degrees);
        for ($i = count($bits) - 1; $i >= $m; $i--) {
            if ($bits[$i]) {
                $bits[$i] = 0;
                foreach ($degrees as $e) {
                    $bits[$i - $m + $e] ^= 1;
                }
            }
        }
        return array_slice($bits, 0, $m);
    }
}
