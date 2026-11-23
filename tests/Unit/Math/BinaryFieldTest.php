<?php

/**
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib4\Tests\Unit\Math;

use phpseclib4\Math\BinaryField;
use phpseclib4\Math\BinaryField\Integer;
use phpseclib4\Exception\UnsupportedValueException;
use phpseclib4\Tests\PhpseclibTestCase;

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
    #[\PHPUnit\Framework\Attributes\DataProvider('badBinaryFieldDegrees')]
    public function testBinaryFieldDegreesAreChecked(array $degrees)
    {
        $this->expectException(UnsupportedValueException::class);
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
            'AES' => [[8, 4, 3, 1, 0]],
            'large middle term' => [[200, 197, 0]],
            'degree 4' => [[4, 1, 0]],
            'degree 3' => [[3, 2, 0]],
            'degree 2' => [[2, 1, 0]],
            'degree 1' => [[1, 0]],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('binaryFields')]
    public function testArithmeticMatchesBitByBitReference(array $degrees)
    {
        $field = new BinaryField(...$degrees);
        $m = $degrees[0];
        $length = (int) ceil(($m + 1) / 8);
        for ($i = 0; $i < 5; $i++) {
            $a = self::pseudoRandomBytes((int) ceil($m / 8), "a$i");
            $b = self::pseudoRandomBytes((int) ceil($m / 8), "b$i");
            // as many bytes as a product of two field elements, and many more
            $c = self::pseudoRandomBytes((int) ceil((2 * $m - 1) / 8), "c$i");
            $d = self::pseudoRandomBytes(3 * strlen($a) + 100, "d$i");

            $x = self::reduce(self::toBits($a), $degrees);
            $y = self::reduce(self::toBits($b), $degrees);
            $product = self::reduce(self::multiply($x, $y), $degrees);
            $square = self::reduce(self::multiply($x, $x), $degrees);

            $a = $field->newInteger($a);
            $b = $field->newInteger($b);
            $this->assertSame(self::toHex($x, $length), $a->toHex());
            $this->assertSame(self::toHex($x, $length), $a->negate()->toHex());
            $this->assertSame(self::toHex($product, $length), $a->multiply($b)->toHex());
            $this->assertSame(self::toHex($square, $length), $a->multiply($a)->toHex());
            $this->assertSame(self::toHex(self::reduce(self::toBits($c), $degrees), $length), $field->newInteger($c)->toHex());
            $this->assertSame(self::toHex(self::reduce(self::toBits($d), $degrees), $length), $field->newInteger($d)->toHex());
        }
    }

    public function testRandomIntegerCoversTheField()
    {
        $field = new BinaryField(163, 7, 6, 3, 0);
        for ($i = 0; $i < 10; $i++) {
            $length = $field->randomInteger()->toBigInteger()->getLength();
            // a uniform draw has 32 bits or fewer with probability 2^-131
            $this->assertGreaterThan(32, $length);
            $this->assertLessThanOrEqual(163, $length);
        }
    }

    public function testFieldsWithTheSamePolynomialShareTheirReduction()
    {
        $a = self::reduction(new BinaryField(163, 7, 6, 3, 0));

        $this->assertSame($a, self::reduction(new BinaryField(163, 3, 6, 7, 0)));
        $this->assertNotSame($a, self::reduction(new BinaryField(163, 7, 6, 2, 0)));
    }

    /**
     * @return callable the function that reduces the field's elements
     */
    private static function reduction(BinaryField $field): callable
    {
        $id = (new \ReflectionProperty(BinaryField::class, 'instanceID'))->getValue($field);
        return (new \ReflectionProperty(Integer::class, 'reduce'))->getValue()[$id];
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
