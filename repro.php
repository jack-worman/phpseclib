<?php
// On Windows, PHP builds the socket pair from two TCP sockets on 127.0.0.1
$domain = PHP_OS_FAMILY === 'Windows' ? STREAM_PF_INET : STREAM_PF_UNIX;
[$client, $server] = stream_socket_pair($domain, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
stream_set_timeout($client, 2);

fwrite($server, str_repeat('x', 1500));
usleep(100000);

function timed_read($name, $client)
{
    $start = microtime(true);
    $data = fread($client, 1024);
    printf("%s: %d bytes in %.3f s, timed_out: %s\n", $name, strlen($data), microtime(true) - $start,
        var_export(stream_get_meta_data($client)['timed_out'], true));
}

// takes all 1500 bytes into the read buffer and returns the first 1024
timed_read('first fread', $client);
// returns the other 476 from the read buffer
timed_read('second fread', $client);
