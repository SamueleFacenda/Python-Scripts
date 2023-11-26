<?php

$url = $_GET['url'];

$regex = '/^https:\/\/www\.corsi\.univr\.it\/documenti\/VoceMenuCS\/documento\/documento[0-9]+\.pdf$/';
if (!preg_match($regex, $url)) {
    die("invalid url");
}

header("Content-Type: application/pdf");
header("Content-Disposition: inline; filename=\"orario.pdf\"");

echo file_get_contents($url);