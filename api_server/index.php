<?php

    if(!empty($_GET['redirect_uri'])) {
        $uri=$_GET['redirect_uri'];
    }

    if(!empty($_GET['oauth2_signature'])) {
        $signature=$_GET['oauth2_signature'];
    }

    if(!empty($_GET['oauth2_consumer_key'])) {
        $consumer_key=$_GET['oauth2_consumer_key'];
    }

    if(!empty($_GET['consumer_secret'])) {
        $consumer_secret=$_GET['consumer_secret'];
    }

    if(!empty($_POST['allow'])) {
        $allow=$_POST['allow'];
    }

    if(!empty($_POST['deny'])) {
        $deny=$_POST['deny'];
    }

    if(!empty($allow))  {

        if(strcmp($consumer_key,"fERxiilWmHnseqa4ur")==0 && strcmp($consumer_secret,"BQZIhhRa1Qyeq1v5sBe44zUPzMn"==0)) {
            $uri = rtrim($uri,"/");
            $uri .= "?token=Qwerty753@SAM";
            header('Location: ' . $uri, true, 301);
            die();
        }
        else {
            header('Location: ' . $uri, true, 301);
            die();  
        }
    }
    else if(!empty($deny)) {
        header('Location: ' . $uri, true, 301);
        die();
    }
?>

<!DOCTYPE html>
<html>
    <head>
        <title>LoginByOAuth</title>
        <link rel="stylesheet" href="css/style.css" type="text/css" media="all">
    </head>

    <body>
        <div class="container">
            <h1>An Application Would Like To Connect Your Account</h1>
            <div class="contact-form">
	            <div class="signin">
                    <form method="post">
	                    <h2>Allow Sample App Access?</h2>
                        <input type="submit" name="allow" value="Allow" />
                        <input type="submit" name="deny" value="Deny" />						 
                    </form>
	            </div>
	        </div> 
        </div>

        <div class="footer">
            <p>The app sample app by SAMEER SENGAR would like the ability to access your basic informations.</a></p>
        </div>

    </body>
</html>
