<?php

	ini_set("allow_url_fopen", 1);
	include ('./oauth2.php');
	include ('./config.inc.php'); 
	error_reporting(E_ALL);

	if(!empty($_GET['token'])) {
		$token=$_GET['token'];	
		sleep(2);
		$url = "http://localhost/OAuth_Server_PHP/client+oauth_server/profile.php?token=".$token;
		header('Location: ' . $url, true, 301);
   		die();
	}

	if(!empty($_POST['authen'])) {
		$authen=$_POST['authen'];
		$argumentsAsObject = Array (
			'v'=>'2.0',
		  	'output'=>'json',
		  	'redirect_uri'=>'http://localhost/OAuth_Server_PHP/client+oauth_server/',
		  	/**
		   		* Though signature is being passed, for simplicity let us use simple authentication using api key
		   		* and consumer secret.
		   		* In actual scenerio signature is enough for authentication.
			*/
		  	'consumer_secret'=>$consumerSecret
	  	);
  
	  	$path = "http://localhost/OAuth_Server_PHP/api_server/";
  
	  	$oauth2 = new OAuth2($apiKey,$consumerSecret);
	   
	  	$url = $oauth2->sign ( Array (
			'action'=>'GET',
			'path'=>$path,
			'parameter'=>$argumentsAsObject,

			'signature'=> Array (
				'consumer_key'=>$apiKey,
				'consumer_secret'=>$consumerSecret
			)
		));
		header('Location: ' . $url['signed_url'], true, 301);
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

			<h1>Log In</h1>
     		<div class="contact-form">

	 			<div class="signin">

     				<form method="post">

	     				<input type="text" class="user" value="Enter Your Username" onfocus="this.value = '';" onblur="if (this.value == '') {this.value = 'Enter Your Username';}" />
		 				<input type="password" class="pass" value="Password" onfocus="this.value = '';" onblur="if (this.value == '') {this.value = 'Password';}" />
         				<input type="submit" value="Login" />
		 				<input type="submit" name='authen' value="LogIn By OAuth2" />					
		 				<!--<p><a href="http://localhost/OAuth_Server_PHP/Oauth_server/index1.php">LogIn By OAuth2</a></p> -->

     				</form>

	 			</div>

	 		</div> 

		</div>

	</body>

</html>
