<?php

    function getBasicInfo() {

        // return a fake API response
        $api_response = array(
            'name' => 'Sameer',
            'email'=> 'sengar.sameer@gmail.com',
            'age'=> '21',
            'city' => 'Jammu'
        );
            
        return json_encode($api_response);

    }

    if(!empty($_GET['token'])) {
        $token=$_GET['token'];
    }

    if(!empty($_GET['redirect_uri'])) {
        $uri=$_GET['redirect_uri'];
    }

    if(strcmp($token,"Qwerty753@SAM")==0) {
        $obj=getBasicInfo();
        header('Content-type: application/json');
        echo $obj;
    }
    else {
        header('Location: ' . $uri, true, 301);
        die();
    }

?>