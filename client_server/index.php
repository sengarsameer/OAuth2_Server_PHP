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
     <form>
	     <input type="text" class="user" value="Enter Your Username" onfocus="this.value = '';" onblur="if (this.value == '') {this.value = 'Enter Your Username';}" />
		 <input type="password" class="pass" value="Password" onfocus="this.value = '';" onblur="if (this.value == '') {this.value = 'Password';}" />
         <input type="submit" value="Login" />					
		 <p><a href="http://localhost/OAuth_Server_PHP/Oauth_server/index1.php">LogIn By OAuth</a></p>  
     </form>
	 </div>
	 </div> 
</div>
</body>
</html>
