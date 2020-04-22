<?php
error_reporting(0);

$link = mysqli_connect("localhost", "databasename","database-password");
$database = mysqli_select_db($link, "databasename");
$user = $_GET['username'];
$password = $_GET['pass'];
$hwid = $_GET['hwid'];
$tables = "users";

$sql = "SELECT * FROM ". $tables ." WHERE username = '". mysqli_real_escape_string($link,$user) ."'" ;
$result = $link->query($sql);
if ($result->num_rows > 0) {
    // Outputting the rows
    while($row = $result->fetch_assoc())
    {
        
        $password = $row['pass'];
      
        $plain_pass = $_GET['pass'];
        $stored_pass = md5($plain_pass);
      
        function Redirect($url, $permanent = false)
        {
            if (headers_sent() === false)
            {
                header('Location: ' . $url, true, ($permanent === true) ? 301 : 302);
            }
        exit();
        }
        
        if($stored_pass != $row['pass'])
        {
               $myVar = htmlspecialchars("0", ENT_QUOTES); 
                 echo($myVar);    // Wrong pass, user exists
        }
        else
        {
            
             if (strlen($row['hwid']) > 1)
        {
            if ($hwid != $row['hwid'])
            {
                 $myVar = htmlspecialchars("0", ENT_QUOTES); 
                 echo($myVar);    // Correct pass
            }
            else
            {
                $myVar = htmlspecialchars("1", ENT_QUOTES); 
                 echo($myVar);    // Correct pass
            }
        }
         else
        {
            $sql = "UPDATE ". $tables ." SET hwid='$hwid' WHERE username='$username'";
            if(mysqli_query($link, $sql))
            {
               
            }
            else
            {
               
            }
        }
            
            
              
        }
        
     
    }
}  
?>