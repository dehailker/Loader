<?php
error_reporting(0);

$link = mysqli_connect("localhost", "databasename","database-password");
$database = mysqli_select_db($link, "databasename");

$user = $_GET['username'];
$hwid = $_GET['hwid'];
$kalanzaman = $_GET['time'];
$tables = "users";
$aktif = 1;
$cur_time = time();
$to_time = strtotime('31-12-2020');
$time = $to_time - $cur_time;

$sql = "SELECT * FROM ". $tables ." WHERE hwid = '". mysqli_real_escape_string($link,$hwid) ."'" ;

$result = $link->query($sql);
if ($result->num_rows > 0) {
    // Outputting the rows
    while($row = $result->fetch_assoc())
    {


        $user = $row['username'];

        if (strlen($row['hwid']) > 1)
        {
            
                
                 $myVar = htmlspecialchars("$user", ENT_QUOTES); 
                 echo($myVar);   
                
        }
             

    }
}  
?>





