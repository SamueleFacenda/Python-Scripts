<?php

// read the href from the file
$fp = fopen('href.txt', 'r');
$last_time = fgets($fp);
$href = fgets($fp);
fclose($fp);

// if the href is older than 1 hour, update it
if (time() - $last_time > 3600) {
    include_once 'update.php';
}
?>