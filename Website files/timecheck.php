<?php
error_reporting(0);

$link = mysqli_connect("localhost", "databasename","database-password");
$database = mysqli_select_db($link, "databasename");

$user = $_GET['username'];
$tables = "users";
$tables2 = "users2";
$cur_time = time();
$to_time = strtotime('31-12-2020');
$time = $to_time - $cur_time;
$durum = 0;

$sql = "SELECT * FROM ". $tables ." WHERE username = '". mysqli_real_escape_string($link,$user) ."'" ;

$result = $link->query($sql);
if ($result->num_rows > 0) {
    // Outputting the rows
    while($row = $result->fetch_assoc())
    {

        $timeleft = $row['time_left'];
        $grup = $row['durum'];

        $math = $timeleft - $cur_time;
         $times = $math / 86400;
           
      $myVar = htmlspecialchars((int)$times, ENT_QUOTES); 
       $myVar2 = htmlspecialchars(" Day", ENT_QUOTES); 
                 echo($myVar);  echo($myVar2);
     
     


        

    }
}  
?>





