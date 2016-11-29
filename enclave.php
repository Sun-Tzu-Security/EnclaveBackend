<?php
	/*
	 * File: enclave.php
	 * Author: Dylan "haifisch" Laws
	 * License; MIT License, see LICENSE included with source. 
	 */

    error_reporting(E_ERROR | E_WARNING | E_PARSE);

    $action = $_GET['action'];
    global $server_user_directory;
    $server_user_directory = '/var/www/html/enclave/users/';

    // initial sanity checks
    if (empty($action)) { // get action
        result("action type is missing!", "init", 1);
    }

    if (empty(server_public_key())) {
        result("server_public_key returned empty, server may be misconfigured for enclave!", "init", 1);
    }

    // shared methods
    /* 
        Function; result
        Description; takes in message and action name w/ error code to be returned in json format. die with json object
    */
    function result($message, $cAction, $errorCode) {
        die(json_encode(['result' => $message, 'called' => $cAction, 'error' => $errorCode]));
    }

    /* 
        Function; checkFile
        Description; takes in directory and checks if file exists there
    */
    function checkFile($fileDir) {
        if (file_exists($fileDir)){
            return true;
        } else {
            return false;
        }
        clearstatcache();
    }

    /* 
        Function; validatePublicKey
        Description; takes in public key and checks its size, if not 32 bytes long reject it
    */
    function validatePublicKey($publicKey) {
        $publicKey = base64_decode($publicKey);
        if ($publicKey === FALSE) {
            return false;
        }
        if (strlen($publicKey) < 32) {
            return false;
        }
        if (strlen($publicKey) > 32) {
            return false;
        }
        if (strlen($publicKey) == 32) {
            return true;
        }
        return false;
    }

    /* 
        Function; validateSignature
        Description; takes in signature and checks its size, if not 32 bytes long reject it
    */
    function validateSignature($signature) {
        $signature = base64_decode($signature);
        if ($signature === FALSE) {
            return false;
        }
        if (strlen($signature) < 64) {
            return false;
        }
        if (strlen($signature) > 64) {
            return false;
        }
        if (strlen($signature) == 64) {
            return true;
        }
        return false;
    }

    /* 
        Function; server_public_key
        Description; generates and returns root pub
    */
    function server_public_key() {
      $contents = file_get_contents("/etc/enclave/server_root.pem");
      $private = curve25519_private($contents);
      $public  = curve25519_public($private);
      $contents = null;
      $private = null;
      return $public;
    }

    // enclave api functions
    /* 
        Function; user_check_public_key
        Description; checks user_pub POST variable, base64 decodes the POST'd pub, SHA256 the bytes and check the user directory with the hashed ID
    */
    function user_check_public_key() {
        if (isset($_POST['user_pub'])) {
            $user_pub = $_POST['user_pub'];
        } else {
            result("missing user_pub from POST", "user_check_public_key", 1); // exit 
        }

        $user_pub = str_replace('-', '+', $user_pub);
        $user_pub = str_replace('_', '/', $user_pub);
        $user_pub = str_replace('~', '=', $user_pub);

        if (!validatePublicKey($user_pub)) {
            result("user_pub size is invalid!", "user_check_public_key", 1);
        }

        $hashedID = hash("sha256", base64_decode($user_pub));
        $globalUserDir = $GLOBALS['server_user_directory'].$hashedID;
        $globalPubDir = $globalUserDir.'/pub.pub'; 
        if (checkFile($globalPubDir)) {
            result("public key exists", "user_check_public_key", 0);
        } else {
            result("public key does not exist", "user_check_public_key", 1);
        }
    }

    /* 
        Function; user_submit_new_public_key
        Description; submit new public key to the server, checks if user directory and user pub exists already exists, if not it creates them and writes a new pub 
    */
    function user_submit_new_public_key()
    {
        if (isset($_POST['user_pub'])) {
            $user_pub = $_POST['user_pub'];
        } else {
            result("missing user_pub from POST", "user_submit_new_public_key", 1); // exit 
        }

        if (isset($_POST['key_signature'])) {
            $signature = $_POST['key_signature'];
        } else {
            result("missing key_signature from POST", "user_submit_new_public_key", 1); // exit 
        }

        $user_pub = str_replace('-', '+', $user_pub);
        $user_pub = str_replace('_', '/', $user_pub);
        $user_pub = str_replace('~', '=', $user_pub);

        $signature = str_replace('-', '+', $signature);
        $signature = str_replace('_', '/', $signature);
        $signature = str_replace('~', '=', $signature);

        if (!validatePublicKey($user_pub)) {
            result("user_pub size is invalid!", "user_submit_new_public_key", 1);
        }

        if (!validateSignature($signature)) {
            result("signature size is invalid!", "user_submit_new_public_key", 1);
        }

        $verified  = curve25519_verify(base64_decode($user_pub), base64_decode($user_pub), base64_decode($signature)) == 0;
        if (!$verified) {
            result("signature verification failed", "user_submit_new_public_key", 1); // exit 
        }

        $hashedID = hash("sha256", base64_decode($user_pub));
        $globalUserDir = $GLOBALS['server_user_directory'].$hashedID;
        $globalPubDir = $globalUserDir.'/pub.pub';  

        // check if php file
        if (strpos($user_pub,'<?php') !== false) {
          result("submitted pub is invalid!", "user_submit_new_public_key", 1);
        }
        // check for user directory
        if (!checkFile($globalUserDir)) {
          mkdir($globalUserDir, 0755, true) or result("user directory could not be created", "user_submit_new_public_key", 1);
        } else {
          result("user directory already exists, wont continue.", "user_submit_new_public_key", 1);
        }
        // check if queue directory exists
        if (!checkFile($globalUserDir.'/queue')) {
          $newDir = $globalUserDir.'/queue';
          mkdir($newDir, 0755, true) or result("user queue directory could not be created", "user_submit_new_public_key", 1);
        }
        // open pub file
        $pubFile = fopen($globalPubDir, "w") or result("couldn't create public key file on server", "user_submit_new_public_key", 1);;
        fwrite($pubFile, $user_pub); // write pub
        fclose($pubFile); // close file
        result("public key written successfully!", "user_submit_new_public_key", 0); // exit 
    }

    /* 
        Function; user_check_queue
        Description; checks users messages and returns list of ids 
    */
    function user_check_queue()
    {
        if (isset($_POST['user_pub'])) {
            $user_pub = $_POST['user_pub'];
        } else {
            result("missing user_pub from POST", "user_check_queue", 1); // exit 
        }

        $user_pub = str_replace('-', '+', $user_pub);
        $user_pub = str_replace('_', '/', $user_pub);
        $user_pub = str_replace('~', '=', $user_pub);

        if (!validatePublicKey($user_pub)) {
            result("user_pub size is invalid!", "user_check_queue", 1);
        }

        $hashedID = hash("sha256", base64_decode($user_pub));
        $globalUserDir = $GLOBALS['server_user_directory'].$hashedID;
        
        $msgs = array_diff(scandir($globalUserDir.'/queue/', 1), array('..', '.', '.DS_Store'));
        if (count($msgs) > 0) {
            die(json_encode(['msgs' => $msgs, 'called' => 'user_check_queue', 'error' => 0]));
        }else {
            result("no messages found in queue", "user_check_queue", 1);
        }
    }

    /* 
        Function; user_get_public_key
        Description; checks users messages and returns list of ids 
    */
    function user_get_public_key()
    {
        if (isset($_POST['user_pub'])) {
            $user_pub = $_POST['user_pub'];
        } else {
            result("missing user_pub from POST", "user_get_public_key", 1); // exit 
        }

        $user_pub = str_replace('-', '+', $user_pub);
        $user_pub = str_replace('_', '/', $user_pub);
        $user_pub = str_replace('~', '=', $user_pub);

        if (!validatePublicKey($user_pub)) {
            result("user_pub size is invalid!", "user_get_public_key", 1);
        }

        if (isset($_POST['reciever_id'])) {
            $reciever_id = $_POST['reciever_id'];
        } else {
            result("missing reciever_id from POST", "user_get_public_key", 1); // exit 
        }

        $hashedID = hash("sha256", base64_decode($user_pub));
        $globalUserDir = $GLOBALS['server_user_directory'].$hashedID;
        
        $receiverPub = $GLOBALS['server_user_directory'].$reciever_id.'/pub.pub';
        if (checkFile($receiverPub)) {
            $pub = file_get_contents($receiverPub, true);
            die(json_encode(['pub' => $pub, 'called' => 'user_get_public_key', 'error' => 0]));
        }else {
            result("public key does not exist for provided id", "user_get_public_key", 1);
        }
    }

    /* 
        Function; user_send_message
        Description; Takes in encrypted message, message signature, creates timestamp and packages message for storage
    */
    function user_send_message()
    {
        $timestamp = time();
        if (isset($_POST['user_pub'])) {
            $user_pub = $_POST['user_pub'];
        } else {
            result("missing user_pub from POST", "user_send_message", 1); // exit 
        }

        $user_pub = str_replace('-', '+', $user_pub);
        $user_pub = str_replace('_', '/', $user_pub);
        $user_pub = str_replace('~', '=', $user_pub);

        if (!validatePublicKey($user_pub)) {
            result("user_pub size is invalid!", "user_send_message", 1);
        }

        if (isset($_POST['reciever_id'])) {
            $reciever_id = $_POST['reciever_id'];
        } else {
            result("missing reciever_id from POST", "user_send_message", 1); // exit 
        }

        if (isset($_POST['message_signature'])) {
            $message_signature = $_POST['message_signature'];
        } else {
            result("missing message_signature from POST", "user_send_message", 1); // exit 
        }

        $message_signature = str_replace('-', '+', $message_signature);
        $message_signature = str_replace('_', '/', $message_signature);
        $message_signature = str_replace('~', '=', $message_signature);

        if (!validateSignature($message_signature)) {
            result("signature size is invalid!", "user_send_message", 1);
        }

        if (isset($_POST['message_data'])) {
            $message_data = $_POST['message_data'];
        } else {
            result("missing message_data from POST", "user_send_message", 1); // exit 
        }

       

        $hashedID = hash("sha256", base64_decode($user_pub));
        $globalUserDir = $GLOBALS['server_user_directory'].$hashedID;

        $receiverPub = $GLOBALS['server_user_directory'].$reciever_id.'/pub.pub';
        if (checkFile($receiverPub)) {
            $packageID = substr(hash("sha256",$hashedID.$reciever_id.$timestamp), 0, -49);
            $message_package = array(
                "message_signature" => $message_signature,
                "message_data" => $message_data,
                "sender" => $hashedID,
                "timestamp" => $timestamp,
                "message_id" => $packageID,
            ); 
            // TODO; encrypt message package before storage on server
            //
            //
            $encoded_package = base64_encode(json_encode($message_package));
            $recieverQueueDirectory = $GLOBALS['server_user_directory'].$reciever_id.'/queue/';
            $recieverQueueFileDir = $recieverQueueDirectory .$packageID;
            $package_file = fopen($recieverQueueFileDir, "w") or result("couldn't create public key file on server", "user_send_message", 1);
            fwrite($package_file, $encoded_package); // write message
            fclose($package_file); // close file
            result("message written successfully!", "user_send_message", 0); // exit 
        }else {
            result("public key does not exist for provided id, user may not exist", "user_send_message", 1);
        }
    }

    /* 
        Function; user_read_message
        Description; Takes in user public key and message id, if message exists it echos the encrypted package
    */
    function user_read_message()
    {
        if (isset($_POST['user_pub'])) {
            $user_pub = $_POST['user_pub'];
        } else {
            result("missing user_pub from POST", "user_read_message", 1); // exit 
        }

        $user_pub = str_replace('-', '+', $user_pub);
        $user_pub = str_replace('_', '/', $user_pub);
        $user_pub = str_replace('~', '=', $user_pub);

        if (!validatePublicKey($user_pub)) {
            result("user_pub size is invalid!", "user_read_message", 1);
        }

        if (isset($_POST['message_id'])) {
            $message_id = $_POST['message_id'];
        } else {
            result("missing message_id from POST", "user_read_message", 1); // exit 
        }

        $hashedID = hash("sha256", base64_decode($user_pub));
        $user_directory = $GLOBALS['server_user_directory'].$hashedID;
        $message_directory = $user_directory.'/queue/'.$message_id;
        if (checkFile($message_directory)) {
            $msg = base64_decode(file_get_contents($message_directory, true));
            $msg = json_decode($msg);
            die(json_encode(['package' => $msg, 'called' => 'user_read_message', 'error' => 0]));
        } else {
            result("message with id ".$message_id." not found!", "user_read_message", 1); // exit   
        }

    }

    /* 
        Function; user_delete_message
        Description; Takes in user public key and message id, if message exists it echos the encrypted package
    */
    function user_delete_message()
    {
        if (isset($_POST['user_pub'])) {
            $user_pub = $_POST['user_pub'];
        } else {
            result("missing user_pub from POST", "user_delete_message", 1); // exit 
        }

        $user_pub = str_replace('-', '+', $user_pub);
        $user_pub = str_replace('_', '/', $user_pub);
        $user_pub = str_replace('~', '=', $user_pub);

        if (!validatePublicKey($user_pub)) {
            result("user_pub size is invalid!", "user_read_message", 1);
        }

        if (isset($_POST['message_id'])) {
            $message_id = $_POST['message_id'];
        } else {
            result("missing message_id from POST", "user_delete_message", 1); // exit 
        }

        if (isset($_POST['signature'])) {
            $signature = $_POST['signature'];
        } else {
            result("missing signature from POST", "user_delete_message", 1); // exit 
        }
        
        $signature = str_replace('-', '+', $signature);
        $signature = str_replace('_', '/', $signature);
        $signature = str_replace('~', '=', $signature);

        if (!validateSignature($signature)) {
            result("signature size is invalid!", "user_delete_message", 1);
        }

        $hashedID = hash("sha256", base64_decode($user_pub));
        $user_directory = $GLOBALS['server_user_directory'].$hashedID;
        $user_pub_directory = $user_directory.'/pub.pub';
        $message_directory = $user_directory.'/queue/'.$message_id;

        $user_pub = file_get_contents($user_pub_directory, true);
        $user_pub = str_replace('-', '+', $user_pub);
        $user_pub = str_replace('_', '/', $user_pub);
        $user_pub = str_replace('~', '=', $user_pub);

        if (checkFile($message_directory)) {
            $message = base64_decode($user_pub);
            $message .= $message_id;
            $message = hash("sha256", $message);
            $verified  = curve25519_verify(base64_decode($user_pub), $message, base64_decode($signature));
            if ($verified) {
                if (is_file($message_directory))
                {
                    unlink($message_directory);
                    if (!is_file($message_directory)) {
                        result("message deleted!", "user_delete_message", 0); // exit   
                    } else {
                        result("failed to remove message!", "user_delete_message", 1); // exit   
                    }
                }
            } else {
                result("signature verification failed!", "user_delete_message", 1); // exit   
            }
        } else {
            result("message with id ".$message_id." not found!", "user_delete_message", 1); // exit   
        }

    }

    // action parsing 
   	switch ($action) {
        case 'server_pub':
            result(base64_encode(server_public_key()), 'server_pub', 0);
            break;

        case 'check_key':
            user_check_public_key();
            break;

        case 'submit_key':
            user_submit_new_public_key();
            break;

        case 'check_messages':
            user_check_queue();
            break;

        case 'get_pub':
            user_get_public_key();
            break;

        case 'message_send':
            user_send_message();
            break;

        case 'message_read':
            user_read_message();
            break;

        case 'message_delete':
            user_delete_message();
            break;

        default:
            # code...
            break;
   	}

?>