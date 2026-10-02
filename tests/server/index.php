<?php
// For CurlPinningTest: echoes the Host header, or redirects when asked.
if(($_GET['to'] ?? '') !== '') {
  header('Location: ' . $_GET['to'], true, 302);
  exit;
}
echo 'host=' . ($_SERVER['HTTP_HOST'] ?? '');
