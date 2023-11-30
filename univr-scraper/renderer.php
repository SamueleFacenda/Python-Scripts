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
    <!-- preview the pdf in browser viewer -->
    <object data="<?php echo $href; ?>" type="application/pdf" width="100%" height="100%">
        
        <!-- fallback 1, pdfjs view -->
        <iframe title="PDF" src="pdfjs/web/viewer.html?file=<?= $url ?>" width="100%" height="100%">
            
            <!-- fallback 2, drive pdf viewer, very buggi -->
            <iframe src="https://drive.google.com/viewerng/viewer?embedded=true&url=<?= $href ?>" 
                id="iframepdf" onload="iframeLoaded()" onerror="updateIframe()"
                width="100%" height="100%" frameborder="0">
                <h1>click <a href="<?php echo $href; ?>">here</a> to view the file</h1>
            </iframe>
        </iframe>
    </object>
</body>
</html>
