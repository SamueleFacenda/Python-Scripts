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
        <p>Alternative text - include a link <a href="<?php echo $href; ?>">to the PDF!</a></p>
</body>
</html>