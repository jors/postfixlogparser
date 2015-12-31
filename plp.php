<?php

/********************************************/
/* Postfix logparser - by jors, 19 Aug 2013 */
/********************************************/

// ---Start USER CONFIGURABLE---
$DBG = false;
$TXT_OUTPUT = false; // Set to 'true' for TXT output
$maillog = '/var/log/mail.log'; // Be sure to chmod a+r /var/log/mail.log first
$num_lines = 2000; // More than 10000 lines can take long way to complete :(
// ---End USER CONFIGURABLE---

/*************/
/* FUNCTIONS */
/*************/

function microtime_float(){
 list($useg, $seg) = explode(" ", microtime());
 return ((float)$useg + (float)$seg);
}

function get_params(){
 global $num_lines, $total_log_num_lines;
 if(isset($_GET))
  if(isset($_GET['l'])){
   if(is_numeric($_GET['l'])){
    $l = (int) $_GET['l'];
    if($l>$total_log_num_lines) $num_lines = $total_log_num_lines;
    else $num_lines = $l;
   }
  }
}

/********/
/* MAIN */
/********/

$start_time = microtime_float();

// -3. Get the number of lines of the mail.log.
$total_log_num_lines = exec("wc -l $maillog | cut -d' ' -f1");

// -2. Get the number of lines to parse, if any.
get_params();

// -1. Save postfix logs in an array.
$rgx_postfix =  '~postfix/.*~';
$log = array();
//$file = file($maillog); // Too much resource (RAM) hungry!
exec("tail -n$num_lines $maillog", $log);
foreach($log as $linea){
 if(preg_match($rgx_postfix, $linea))
  $log[] = explode('\n', $linea);
}

// 0. Array and regexp definitions.
$ar_connect = array();
$ar_disconnect = array();
$ar_mail_track = array();
$ar_reject = array();
$ar_connection_issues = array();
$ar_others = array();
$rgx_connect = '~postfix/smtpd\[(\d+)\]: connect from .*~';
$rgx_disconnect = '~postfix/smtpd\[(\d+)\]: disconnect from .*~';
$rgx_postfixid = '~postfix/[a-z]+\[(\d+)\]: ([A-F0-9]{10}): .*~';
//$rgx_dsn_issues = '~postfix/[a-z]+\[(\d+)\]: ([A-F0-9]{10}): .*(dsn=[3-5]\.[0-9]\.[0-9]).*~';

// 1. First level classification (grouping by postfix ids).
foreach($log as $num_linea => $linea){
 if(preg_match($rgx_connect, $linea[0], $matches)) // Connect
  $ar_connect[$matches[1]] = $matches[0];
 elseif(preg_match($rgx_disconnect, $linea[0], $matches)) // Disconnect
  $ar_disconnect[$matches[1]] = $matches[0];
 elseif(preg_match($rgx_postfixid, $linea[0], $matches)){ // Postfix id's
  if($DBG) echo "linea: $linea[0]\n";
  if(count($ar_mail_track)==0)
   $ar_mail_track[] = $matches[0];
  else {
   $found = 0;
   foreach($ar_mail_track as $key => $value){
    //if(strpos($value, $matches[2]) !== false){ // Item found
    if(preg_match("#postfix/[a-z]+\[(\d+)\]: $matches[2]#", $value)){ // Item found
     if($DBG) echo "Comparant si 'postfix/[a-z]+\[(\d+)\]: $matches[2]' esta a '$value'...'\n";
     if($DBG) echo "Item 'postfix/[a-z]+\[(\d+)\]: $matches[2]' en la lista.\n";
     $ar_mail_track[$key] = $ar_mail_track[$key]." ~ ".$matches[0];
     $found = 1;
     break;
    }
   }
   if($found == 0){
    if($DBG) echo "Item 'postfix/[a-z]+\[(\d+)\]: $matches[2]' NO en la lista.\n";
     $ar_mail_track[] = $matches[0];
   }
   else $found = 0;
  }
  if($DBG) print_r($ar_mail_track);
  if($DBG) echo "---\n\n";
 }
 else { // Catchall
  if(preg_match("~postfix/[a-z]+\[(\d+)\]: statistics.*~", $linea[0], $matches)) continue; // Discard
  elseif(preg_match("~postfix/[a-z]+\[(\d+)\]: warning: dict_nis_init(.*)~", $linea[0], $matches)) continue; // Discard
  elseif(preg_match("~postfix/[a-z]+\[(\d+)\]: connect to ([a-z\d\-]-*[a-z\d\-]*\.[a-z\d]-*[a-z\d]*)+(.*)~", $linea[0], $matches)) // Conn issues
   $ar_connection_issues[] = $matches[0];
  elseif(preg_match("~postfix/[a-z]+\[(\d+)\]: NOQUEUE: reject(.*)~", $linea[0], $matches)) // Reject/Spam
   $ar_reject[] = $matches[0];
  elseif(preg_match($rgx_postfix, $linea[0], $matches2)) $ar_others[] = $matches2[0];
  //else ...
 }
}

// 2. Second level classification (connect/disconnect with Postfix id's).
foreach($ar_connect as $key => $value){
 if($DBG) echo "Searching for pid: $key...\n";
 foreach($ar_mail_track as $key2 => $item){
  if($DBG) echo "In key: $key2...\n";
  if(preg_match("#postfix/[smtpd]+\[$key\]#", $item)){
   $ar_mail_track[$key2] = $value." ~ ".$ar_mail_track[$key2];
   $ar_mail_track[$key2] = $ar_mail_track[$key2]." ~ ".$ar_disconnect[$key];
   unset($ar_connect[$key]);
   unset($ar_disconnect[$key]);
   if($DBG) echo "pid $key found in $item!\n";
   break;
  }
 }
}

// 3. Third level classification (reject/spam pairing).
foreach($ar_connect as $key => $value){
 foreach($ar_reject as $key2 => $item){
  if(preg_match("#postfix/[smtpd]+\[$key\]#", $item)){
   $ar_reject[$key2] = $value." ~ ".$ar_reject[$key2]." ~ ".$ar_disconnect[$key];
   unset($ar_connect[$key]);
   unset($ar_disconnect[$key]);
   break;
  }
 }
}

// 4. Fourth level (others pairing)?
// TODO

// 5. Fifth level (orphan/remaining connect/disconnect pairing)?
// TODO

$stop_time = microtime_float();
$run_time = round($stop_time - $start_time, 2);

if($TXT_OUTPUT){
 echo "ar_connect: (".count($ar_connect)." entries)\n"; print_r($ar_connect);
 echo "\nar_disconnect: (".count($ar_disconnect)." entries)\n"; print_r($ar_disconnect);
 echo "\nar_mail_track: (".count($ar_mail_track)." entries)\n"; print_r($ar_mail_track);
 echo "\nar_connection_issues: (".count($ar_connection_issues)." entries)\n"; print_r($ar_connection_issues);
 echo "\nar_reject: (".count($ar_reject)." entries)\n"; print_r($ar_reject);
 echo "\nar_others: (".count($ar_others)." entries)\n"; print_r($ar_others); echo "\n";
} else { // HTML is fun
 // Folding javascripty. Weeeeee!!!
 echo '<head>
<style type="text/css">
h2 { cursor:pointer; }
.hb { visibility:hidden; display:none; font-size:small; }
.red { background-color:red; color:white; font-weigth:bold; }
.yellow { background-color:yellow; font-weigth:bold; }
.green { background-color:green; color:white; font-weigth:bold; }
.link { font-size:x-small; float:right; color:blue; text-decoration:underline; cursor:pointer; }
.legendtable, .legendtable td { font-size:small; border-spacing:25px; border-collapse: separate }
.bold { font-weight:bold; background-color:grey; font-style:italic; }
</style>
<script type="text/javascript">
function showMeHideMe(c)
{
 var b=document.getElementById(c);
 var d=getComputedStyle(b);
 //if(b.style.visibility=="hidden")
 if(d.visibility=="hidden")
 {
  b.style.visibility="visible";
  b.style.display="inline";
 }
 else
 {
  b.style.visibility="hidden";
  b.style.display="none";
 }
}

function changeText(c)
{
 //var cur_text=document.getElementById(c).innerText;
 //var cur_text_ff=document.getElementById(c).textContent;
 var cur_text=c.innerText;
 var cur_text_ff=c.textContent;
 if(cur_text=="+ Legend" || cur_text_ff=="+ Legend"){
  //document.getElementById(c).innerText="- Legend";
  //document.getElementById(c).textContent="- Legend";
  c.innerText="- Legend";
  c.textContent="- Legend";
 } else {
  //document.getElementById(c).innerText="+ Legend";
  //document.getElementById(c).textContent="+ Legend";
  c.innerText="+ Legend";
  c.textContent="+ Legend";
 }
}
</script>
</head>';

 echo '<body bgcolor="lightgrey"><center><h1>Postfix logparser</h1><span style="font-size:x-small;">(Parsed '.$num_lines.' out of '.$total_log_num_lines.' lines in '.$run_time.' secs)</span><!---span id="legend" class="link" onclick="changeText(\'legend\'); showMeHideMe(\'legendtable\');">+ Legend</span--><span class="link" onclick="changeText(this); showMeHideMe(\'legendtable\');">+ Legend</span>
       <div id="legendtable" class="legendtable hb"></br></br>
        <table border=1 bgcolor=white cellpadding=3>
         <tr>
          <td class="bold">Single/unpaired connections</td>
          <td>Connections that cannot be paired with a sent mail.</td>
         </tr>
         <tr>
          <td class="bold">Single/unpaired disconnections</td>
          <td>Disconnections that cannot be paired with a sent mail. Usually will also exist an initial connection.</td>
         </tr>
         <tr>
          <td class="bold">Tracked mails</td>
          <td>Any initially accepted mail tracking, both successful &amp; unsuccessful deliveries.</td>
         </tr>
         <tr>
          <td class="bold">Connection issues</td>
          <td>Issues related to connetion failures.</td>
         </tr>
         <tr>
          <td class="bold">Rejections</td>
          <td>All kinds of, even Greylisting (temporal rejection).</td>
         </tr>
         <tr>
          <td class="bold">Others</td>
          <td>Everything else not included in previous categories.</td>
         </tr>
        </table></br></div><hr></center>';
 if(count($ar_connect)>0){
  echo '<h2 onclick="showMeHideMe(\'ar_connect\');">Single/unpaired connections ('.count($ar_connect).')</h2><span id="ar_connect" class="hb">';
  foreach($ar_connect as $item) echo htmlentities($item).'</br>';
  echo '</span>';
 }
 if(count($ar_disconnect)>0){
  echo '<h2 onclick="showMeHideMe(\'ar_disconnect\');">Single/unpaired disconnections ('.count($ar_disconnect).')</h2><span id="ar_disconnect" class="hb">';
  foreach($ar_disconnect as $item) echo htmlentities($item).'</br>';
  echo '</span>';
 }
 if(count($ar_mail_track)>0){
  echo '<h2 onclick="showMeHideMe(\'ar_mail_track\');">Tracked mails ('.count($ar_mail_track).')</h2><span id="ar_mail_track" class="hb">';
  foreach($ar_mail_track as $item){
   $clean = str_replace('~', '</br>', htmlentities($item));
   $str = str_replace('removed', '<span class="green">removed</span>', $clean);
   $str = preg_replace("~dsn=[3-5]\.[0-9]\.[0-9]~", '<span class="yellow">\\0</span>', $str);
   echo $str.'</br></br>';
  }
  echo '</span>';
 }
 if(count($ar_connection_issues)>0){
  echo '<h2 onclick="showMeHideMe(\'ar_connection_issues\');">Connection issues ('.count($ar_connection_issues).')</h2><span id="ar_connection_issues" class="hb">';
  foreach($ar_connection_issues as $item) echo htmlentities($item).'</br>';
  echo '</span>';
 }
 if(count($ar_reject)>0){
  $redalert = array('/denied/', '/rejected/', '/blocked/');
  echo '<h2 onclick="showMeHideMe(\'ar_reject\');">Rejections ('.count($ar_reject).')</h2><span id="ar_reject" class="hb">';
  foreach($ar_reject as $item){
   $clean = str_replace('~', '</br>', htmlentities($item));
   $str = str_ireplace('Greylisted', '<span style="background-color:grey;">Greylisted</span>', $clean);
   if($clean == $str) // No replacement? No greylisting, carry on
    $str = preg_replace($redalert, '<span class="red">\\0</span>', $str);
   echo $str.'</br></br>';
  }
  echo '</span>';
 }
 if(count($ar_others)){
  echo '<h2 onclick="showMeHideMe(\'ar_others\');">Others ('.count($ar_others).')</h2><span id="ar_others" class="hb">';
  foreach($ar_others as $item) echo htmlentities($item).'</br>';
  echo '</span></body>';
 }
}
?>
