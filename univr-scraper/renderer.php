<?php

include_once 'parser.php';
$href = urldecode($href);
// dumb cors security bypass
$url = "../../proxy.php?url=$href";
$url = urlencode($url);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Orario infermieristica aggiornato</title>
    <style>
        html, body {
            margin: 0;
            padding: 0;
            height: 100%;
        }
    </style>
</head>
<body>
<script>

function iframeLoaded() {
    console.log('iframe loaded');
    //clearInterval(interval);
}
function updateIframe() {
    capture_resurces = performance.getEntriesByType("resource");
    pdf_resource = capture_resurces.filter(function(res) {
        return res.initiatorType == 'iframe' && res.name.endsWith('.pdf');
    })[0];
    console.log(pdf_resource);
    var iframe = document.getElementById('iframepdf');
    //iframe.src = iframe.src;

}
</script>
    <!-- preview the pdf in $href -->
    <!--
    <object data="<?php echo $href; ?>" type="application/pdf" width="100%" height="100%">
        <iframe src="https://drive.google.com/viewerng/viewer?embedded=true&url=<?= $href ?>" 
            id="iframepdf" onload="iframeLoaded()" onerror="updateIframe()"
            width="100%" height="100%" frameborder="0">
            <h1>click <a href="<?php echo $href; ?>">here</a> to view the file</h1>
        </iframe>
    </object>
-->
    <iframe title="PDF" src="pdfjs/web/viewer.html?file=<?= $url ?>" width="100%"
    height="100%"></iframe>
<script>
//interval = setInterval(function() {
//    updateIframe();
//}, 1000 * 3);


</script>
</body>
</html>
