<?php
	/*
		File: index.php
		Copyright 2016 Sun Tzu Security
	*/
	// I'll improve code comments #son
	error_reporting(E_ERROR | E_WARNING | E_PARSE);

	if ($_GET['action']) {
		require('enclave.php');
	} else {
		die("Enclave API Endpoint");
	}
?>
