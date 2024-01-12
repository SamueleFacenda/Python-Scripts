<?php
//suppress warnings for DOMDocument
libxml_use_internal_errors(true);

$url = 'https://www.corsi.univr.it/?ent=cs&id=474&menu=studiare&tab=orario-lezioni&lang=it';
$match = 'Orario 1° anno';
$xquery = "//a[contains(.,'$match')]";

// Create DOMdocument from URL
$html = new DOMDocument();
$html->loadHTMLFile($url);

// find the a tag with the xpath
$xpath = new DOMXPath($html);
$href = $xpath->query($xquery);
// get the href attribute
$href = $href->item(0)->getAttribute('href');
$href = "https://www.corsi.univr.it$href";

// save value to file
$fp = fopen('href.txt', 'w');
fwrite($fp, time());
fwrite($fp, "\n");
fwrite($fp, $href);
fclose($fp);

$file = $_SERVER['REQUEST_URI'];
// get the file name
$file = substr($file, strrpos($file, '/') + 1);
if ($file == "update.php") {
    echo "<h1>Aggiornato</h1>";
}
?>
