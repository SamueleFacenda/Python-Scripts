<?php

// read the href from the file
$fp = fopen('href.txt', 'r');
$last_time = fgets($fp);
$href = fgets($fp);
fclose($fp);

?>
