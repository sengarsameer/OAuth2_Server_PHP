<?php
    include ('oauth2.php');
    include ('config.inc.php');

    /**
     * These terms are defined in config.inc.php
     
     * $apiKey
     * $consumerSecret
     * accessToken
     * tokenSecret
     
    */

    $path = "http://localhost/OAuth_Server_PHP/Oauth_server/index.php";

    //$argumentsAsString = "term=mac%20and+me&expand=formats,synopsis&max_results=1";

    $argumentsAsObject = Array (
        'term'=>'Hello World',
        'expand'=>'formats,synopsis',
        'max_results'=> '1',
        'v'=>'2.0',
        'output'=>'json'
    );

    $oauth2 = new OAuth2($apiKey,$consumerSecret);
    //$oauth2->setParameter($argumentsAsString);
    $oauth2->setPath($path);
    $sample1Results = $oauth2->sign();

    $oauth2->reset();
    $sample2Results = $oauth2->sign ( Array (
        'action'=>'GET',
        'path'=>$path,
        'parameter'=>$argumentsAsObject)
    );

    $oauth2 = new OAuth2();
    $sample3Results = $oauth2->sign ( 
        Array (
            'path'=>'http://api.netflix.com/catalog/people',

            'parameter'=> Array (
                'term'=>'Harrison Ford',
                'max_results'=>'5'
            ),

            'signature'=> Array (
                'consumer_key'=>$apiKey,
                'consumer_secret'=>$consumerSecret,
                'access_token'=>$accessToken,
                'access_secret'=>$tokenSecret
            )
        )          

    );
?>


<html>
    <head>
        <title>Test Document</title>
    </head>
    <body>
        <h1>Test Document</h1>
        <ol>
            <li><a href="<?php print $sample1Results['signed_url'] ?>">First Link</a><br />
            </li>
            <li><a href="<?php print $sample2Results['signed_url'] ?>">Second Link</a>
            <?php /*
            <pre> <?php print_r($sample2Results); ?> </pre>
            */ ?>
            </li>
            <li><a href="<?php print $sample3Results['signed_url'] ?>">Third Link</a></li>
        </ol>
        <a href="index.php">Source for index</a><br />
        <a href="OAuthSimple.php">Source for OAuthSimple.php</a>
    </body>
</html>