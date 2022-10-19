<?php

declare(strict_types=1);

namespace phpseclib3\Net;

use phpseclib3\Common\Functions\Strings;

class Logger
{
    /**
     * Returns the message numbers
     *
     * @see \phpseclib3\Net\SSH2::getLog()
     */
    public const LOG_SIMPLE = 1;
    /**
     * Returns the message content
     *
     * @see \phpseclib3\Net\SSH2::getLog()
     */
    public const LOG_COMPLEX = 2;
    /**
     * Outputs the content real-time
     */
    public const LOG_REALTIME = 3;
    /**
     * Dumps the content real-time to a file
     */
    public const LOG_REALTIME_FILE = 4;
    /**
     * Outputs the message numbers real-time
     */
    public const LOG_SIMPLE_REALTIME = 5;
    /**
     * Make sure that the log never gets larger than this
     *
     * @see \phpseclib3\Net\SSH2::getLog()
     */
    public const LOG_MAX_SIZE = 1048576; // 1024 * 1024

    /**
     * Message Number Log
     *
     * @see self::getLog()
     */
    private array $message_number_log = [];

    /**
     * Message Log
     *
     * @see self::getLog()
     */
    private array $message_log = [];

    /**
     * Current log size
     *
     * Should never exceed self::LOG_MAX_SIZE
     *
     * @see self::_send_binary_packet()
     * @see self::_get_binary_packet()
     */
    private int $log_size;

    /**
     * Real-time log file pointer
     *
     * @see self::_append_log()
     * @var resource|closed-resource
     */
    private $realtime_log_file;

    /**
     * Real-time log file size
     *
     * @see self::_append_log()
     */
    private int $realtime_log_size;

    /**
     * Real-time log file wrap boolean
     *
     * @see self::_append_log()
     */
    private bool $realtime_log_wrap;

    /**
     * Log Boundary
     *
     * @see self::_format_log()
     */
    private string $log_boundary = ':';

    /**
     * Log Long Width
     *
     * @see self::_format_log()
     */
    private int $log_long_width = 65;

    /**
     * Log Short Width
     *
     * @see self::_format_log()
     */
    private int $log_short_width = 16;

    public function __construct(private readonly int $logType)
    {
    }

    /**
     * Logs data packets
     *
     * Makes sure that only the last 1MB worth of packets will be logged
     */
    public function append_log(string $message_number, string $message): void
    {
        $this->append_log_helper(
            $this->logType,
            $message_number,
            $message,
            $this->message_number_log,
            $this->message_log,
            $this->log_size,
            $this->realtime_log_file,
            $this->realtime_log_wrap,
            $this->realtime_log_size
        );
    }

    /**
     * Logs data packet helper
     *
     * @param resource &$realtime_log_file
     */
    protected function append_log_helper(int $constant, string $message_number, string $message, array &$message_number_log, array &$message_log, int &$log_size, &$realtime_log_file, bool &$realtime_log_wrap, int &$realtime_log_size): void
    {
        // remove the byte identifying the message type from all but the first two messages (ie. the identification strings)
        if (strlen($message_number) > 2) {
            Strings::shift($message);
        }

        switch ($constant) {
            // useful for benchmarks
            case self::LOG_SIMPLE:
                $message_number_log[] = $message_number;
                break;
            case self::LOG_SIMPLE_REALTIME:
                echo $message_number;
                echo PHP_SAPI == 'cli' ? "\r\n" : '<br>';
                @flush();
                @ob_flush();
                break;
            // the most useful log for SSH2
            case self::LOG_COMPLEX:
                $message_number_log[] = $message_number;
                $log_size += strlen($message);
                $message_log[] = $message;
                while ($log_size > self::LOG_MAX_SIZE) {
                    $log_size -= strlen(array_shift($message_log));
                    array_shift($message_number_log);
                }
                break;
            // dump the output out realtime; packets may be interspersed with non packets,
            // passwords won't be filtered out and select other packets may not be correctly
            // identified
            case self::LOG_REALTIME:
                switch (PHP_SAPI) {
                    case 'cli':
                        $start = $stop = "\r\n";
                        break;
                    default:
                        $start = '<pre>';
                        $stop = '</pre>';
                }
                echo $start . $this->format_log([$message], [$message_number]) . $stop;
                @flush();
                @ob_flush();
                break;
            // basically the same thing as self::LOG_REALTIME with the caveat that NET_SSH2_LOG_REALTIME_FILENAME
            // needs to be defined and that the resultant log file will be capped out at self::LOG_MAX_SIZE.
            // the earliest part of the log file is denoted by the first <<< START >>> and is not going to necessarily
            // at the beginning of the file
            case self::LOG_REALTIME_FILE:
                if (!isset($realtime_log_file)) {
                    // PHP doesn't seem to like using constants in fopen()
                    $filename = NET_SSH2_LOG_REALTIME_FILENAME;
                    $fp = fopen($filename, 'w');
                    $realtime_log_file = $fp;
                }
                if (!is_resource($realtime_log_file)) {
                    break;
                }
                $entry = $this->format_log([$message], [$message_number]);
                if ($realtime_log_wrap) {
                    $temp = "<<< START >>>\r\n";
                    $entry .= $temp;
                    fseek($realtime_log_file, ftell($realtime_log_file) - strlen($temp));
                }
                $realtime_log_size += strlen($entry);
                if ($realtime_log_size > self::LOG_MAX_SIZE) {
                    fseek($realtime_log_file, 0);
                    $realtime_log_size = strlen($entry);
                    $realtime_log_wrap = true;
                }
                fwrite($realtime_log_file, $entry);
        }
    }

    /**
     * Returns a log of the packets that have been sent and received.
     *
     * Returns a string if NET_SSH2_LOGGING == self::LOG_COMPLEX, an array if NET_SSH2_LOGGING == self::LOG_SIMPLE and false if !defined('NET_SSH2_LOGGING')
     *
     * @return array|false|string
     */
    public function getLog()
    {
        if (!defined('NET_SSH2_LOGGING')) {
            return false;
        }

        switch ($this->logType) {
            case self::LOG_SIMPLE:
                return $this->message_number_log;
            case self::LOG_COMPLEX:
                $log = $this->format_log($this->message_log, $this->message_number_log);
                return PHP_SAPI == 'cli' ? $log : '<pre>' . $log . '</pre>';
            default:
                return false;
        }
    }

    /**
     * Formats a log for printing
     */
    protected function format_log(array $message_log, array $message_number_log): string
    {
        $output = '';
        for ($i = 0; $i < count($message_log); $i++) {
            $output .= $message_number_log[$i] . "\r\n";
            $current_log = $message_log[$i];
            $j = 0;
            do {
                if (strlen($current_log)) {
                    $output .= str_pad(dechex($j), 7, '0', STR_PAD_LEFT) . '0  ';
                }
                $fragment = Strings::shift($current_log, $this->log_short_width);
                $hex = substr(preg_replace_callback('#.#s', fn ($matches) => $this->log_boundary . str_pad(dechex(ord($matches[0])), 2, '0', STR_PAD_LEFT), $fragment), strlen($this->log_boundary));
                // replace non ASCII printable characters with dots
                // http://en.wikipedia.org/wiki/ASCII#ASCII_printable_characters
                // also replace < with a . since < messes up the output on web browsers
                $raw = preg_replace('#[^\x20-\x7E]|<#', '.', $fragment);
                $output .= str_pad($hex, $this->log_long_width - $this->log_short_width, ' ') . $raw . "\r\n";
                $j++;
            } while (strlen($current_log));
            $output .= "\r\n";
        }

        return $output;
    }

    /**
     * Update packet types in log history
     */
    public function updateLogHistory(string $old, string $new): void
    {
        if ($this->logType == self::LOG_COMPLEX) {
            $this->message_number_log[count($this->message_number_log) - 1] = str_replace(
                $old,
                $new,
                $this->message_number_log[count($this->message_number_log) - 1]
            );
        }
    }

    public function close(): void
    {
        if (isset($this->realtime_log_file) && is_resource($this->realtime_log_file)) {
            fclose($this->realtime_log_file);
        }
    }
}
