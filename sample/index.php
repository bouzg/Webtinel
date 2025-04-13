<?php
echo "Hello, World!";
$time = date("H:i:s");
echo "<br>Current Time: " . $time;

$fruits = array("Apple", "Banana", "Cherry");
echo "<br>First Fruit: " . $fruits[0];

if ($time < "12:00:00") {
    echo "<br>Good Morning!";
} else {
    echo "<br>Good Afternoon!";
}

function addNumbers($a, $b) {
    return $a + $b;
}

$result = addNumbers(5, 10);
echo "<br>Sum of 5 and 10 is: " . $result;
?>
