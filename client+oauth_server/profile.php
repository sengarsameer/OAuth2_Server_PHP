<!DOCTYPE html>
<html>
	<head>
	    <title>LoginByOAuth</title>
	    <link rel="stylesheet" href="css/style.css" type="text/css" media="all">
	</head>

	<body>
        <div class="container">
            <h1>Your Profile</h1>
            <div class="contact-form">
	            <div class="signin">
                    <form>
	                    <h3>Welcome to your profile page-</h3>

                        <?php

                            ini_set("allow_url_fopen", 1);

                            if(!empty($_GET['token'])) {
                                $token=$_GET['token'];         
                            }

                            if(!empty($token)) {
                                $path = "http://localhost/OAuth_Server_PHP/api_server/resource.php?token=".$token;//.'&redirect_uri=http://localhost/OAuth_Server_PHP/client+oauth_server/profile.php';
                                $json = file_get_contents($path);
                                $obj = json_decode($json,true);

                        ?>


                                <table>
                                    <tbody>
       
                                        <tr>           
                                            <td>Name :</td>
                                            <td><?php echo $obj['name']; ?></td>
                                        </tr>

                                        <tr>           
                                            <td>Email :</td>
                                            <td><?php echo $obj['email']; ?></td>
                                        </tr>

                                        <tr>           
                                            <td>Age :</td>
                                            <td><?php echo $obj['age']; ?></td>
                                        </tr>

                                        <tr>           
                                            <td>City :</td>
                                            <td><?php echo $obj['city']; ?></td>
                                        </tr>

                                    </tbody>
                                </table>

                                <?php
                            }       else{
                                        echo "No Data available.";
                                    }
                                ?>

        
                    </form>
	            </div>
	        </div> 
        </div>
    </body>
</html>
