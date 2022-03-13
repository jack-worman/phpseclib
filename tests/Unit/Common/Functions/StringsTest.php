<?php

namespace phpseclib3\Tests\Unit\Common\Functions;

use phpseclib3\Common\Functions\Strings;
use PHPUnit\Framework\TestCase;

class StringsTest extends TestCase
{
    /**
     * @dataProvider provideShift
     * @param string $string
     * @param int $index
     * @param string|false $expectedResult
     * @param string|false $expectedString
     * @return void
     */
    public function testShift($string, $index, $expectedResult, $expectedString)
    {
        $result = Strings::shift($string, $index);
        self::assertSame($expectedResult, $result);
        self::assertSame($expectedString, $string);
    }

    /**
     * @return list<array{string, int, string|false, string|false}>
     */
    public function provideShift()
    {
        return [
            ['', -1, '', ''],
            ['', 0, '', ''],
            ['', 1, '', ''],
            ['word', -5, '', 'word'],
            ['word', -4, '', 'word'],
            ['word', -3, 'w', 'ord'],
            ['word', -2, 'wo', 'rd'],
            ['word', -1, 'wor', 'd'],
            ['word', 0, '', 'word'],
            ['word', 1, 'w', 'ord'],
            ['word', 2, 'wo', 'rd'],
            ['word', 3, 'wor', 'd'],
            ['word', 4, 'word', ''],
            ['word', 5, 'word', ''],
        ];
    }

    /**
     * @dataProvider providePop
     * @param string $string
     * @param int $index
     * @param string|false $expectedResult
     * @param string|false $expectedString
     * @return void
     */
    public function testPop($string, $index, $expectedResult, $expectedString)
    {
        $result = Strings::pop($string, $index);
        self::assertSame($expectedResult, $result);
        self::assertSame($expectedString, $string);
    }

    /**
     * @return list<array{string, int, string|false, string|false}>
     */
    public function providePop()
    {
        return [
            ['', -1, false, ''],
            ['', 0, '', ''],
            ['', 1, '', false],
            ['hello', -6, false, 'hello'],
            ['hello', -5, '', 'hello'],
            ['hello', -4, 'o', 'hell'],
            ['hello', -3, 'lo', 'hel'],
            ['hello', -2, 'llo', 'he'],
            ['hello', -1, 'ello', 'h'],
            ['hello', 0, 'hello', ''],
            ['hello', 1, 'o', 'hell'],
            ['hello', 2, 'lo', 'hel'],
            ['hello', 3, 'llo', 'he'],
            ['hello', 4, 'ello', 'h'],
            ['hello', 5, 'hello', ''],
            ['hello', 6, 'hello', false],
        ];
    }

    /**
     * @dataProvider provideIsStringable
     * @param mixed $var
     * @param bool $expectedResult
     * @return void
     */
    public function testIsStringable($var, $expectedResult)
    {
        self::assertSame($expectedResult, Strings::is_stringable($var));
    }

    /**
     * @return list<array{mixed, bool}>
     */
    public function provideIsStringable()
    {
        return [
            ['', true],
            [eval('class __StringableClass__{function __toString(){}}return new __StringableClass__;'), true],
            [null, false],
            [false, false],
            [true, false],
            [0, false],
            [0.0, false],
            [new \stdClass(), false],
        ];
    }
}
