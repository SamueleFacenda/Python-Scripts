<?php

include_once 'parser.php';

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Orario infermeristica aggiornato</title>
    <style>
        html, body {
            margin: 0;
            padding: 0;
            height: 100%;
        }
    </style>
</head>
<body>
    <!-- preview the pdf in $href -->
    <object data="<?php echo $href; ?>" type="application/pdf" width="100%" height="100%">
        <object data="https://drive.google.com/viewerng/viewer?embedded=true&url=<?= $href ?>" width="100%" height="100%">
            <h1>click <a href="<?php echo $href; ?>">here</a> to view the file</h1>
        </object>
    </object>
</body>
</html>