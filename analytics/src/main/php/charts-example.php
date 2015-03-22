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
<title>Event Engine Charts</title>
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

<img src="charts/IocThreatTypeTop.png" alt="" width="1024" height="768">
<br>
<br>

<img src="charts/IocValueTop.png" alt="" width="1024" height="768">
<br>
<br>

<img src="charts/IocTypeTop.png" alt="" width="1024" height="768">
<br>
<br>

<img src="charts/IocIpTop.png" alt="" width="1024" height="768">
<br>
<br>

<img src="charts/IocDnsTop.png" alt="" width="1024" height="768">
<br>
<br>

<img src="charts/IocIdTop.png" alt="" width="1024" height="768">
<br>
<br>

<img src="charts/DstIpTop.png" alt="" width="1024" height="768">
<br>
<br>

<img src="charts/SrcIpTop.png" alt="" width="1024" height="768">
<br>
<br>

<img src="charts/DstPortTop.png" alt="" width="1024" height="768">
<br>
<br>

<img src="charts/SrcPortTop.png" alt="" width="1024" height="768">
<br>
<br>

<img src="charts/HashKeyTop.png" alt="" width="1024" height="768">
<br>
<br>

<img src="charts/DstMacTop.png" alt="" width="1024" height="768">
<br>
<br>

<img src="charts/SrcMacTop.png" alt="" width="1024" height="768">
<br>
<br>

<img src="charts/EthTypeTop.png" alt="" width="1024" height="768">
<br>
<br>

<img src="charts/IpProtocolTop.png" alt="" width="1024" height="768">
<br>
<br>

</body>

</html>
