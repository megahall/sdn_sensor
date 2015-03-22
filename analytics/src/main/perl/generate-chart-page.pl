#!/usr/bin/env perl

use strict;
use warnings FATAL => 'all';

use Cwd qw(abs_path);
use Data::Dumper;
use File::Basename;

$Data::Dumper::Indent   = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Terse    = 1;

print <<'EOH';
<?php
if (!isset($_SESSION)) {
    session_start();
}
if (isset($_GET['chart_x']) && isset($_GET['chart_y'])) {
    $_SESSION['chart_x'] = $_GET['chart_x'];
    $_SESSION['chart_y'] = $_GET['chart_y'];
}
?>

<html>
<head>
<title>Analytics Engine Charts</title>
<meta http-equiv="refresh" content="5">
</head>

<body onload="setScroll()" onbeforeunload="saveScroll()">

<script type="text/javascript">
<!--
function getScroll() {
    var x = 0, y = 0;
    var position = new Object();
    position.x = document.body.scrollLeft;
    position.y = document.body.scrollTop;
    return position;
};

function saveScroll() {
    var position = getScroll();
    document.getElementById("chart_x").value = position.x;
    document.getElementById("chart_y").value = position.y;
    document.forms["submitPosition"].submit();
}

function setScroll() {
    var x = <?php echo json_encode(isset($_SESSION['chart_x']) ? $_SESSION['chart_x'] : 0); ?>;
    var y = <?php echo json_encode(isset($_SESSION['chart_y']) ? $_SESSION['chart_y'] : 0); ?>;
    if (x && y)
        window.scrollTo(x, y);
}
-->
</script>

<form name="submitPosition" id="submitPosition" action="<?php echo $_SERVER['PHP_SELF']; ?>" method="GET">
    <input name="chart_x" id="chart_x" type="hidden" value="" />
    <input name="chart_y" id="chart_y" type="hidden" value="" />
</form>

EOH

my @chart_names = glob("*.png");
foreach my $chart_name (@chart_names) {
print <<EOE;
<img src="charts/$chart_name" alt="" width="1024" height="768">
<br>
<br>

EOE
}

print <<EOT;
</body>

</html>
EOT
