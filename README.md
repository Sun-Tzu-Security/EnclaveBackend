# Enclave Messenger API
Currently being rewritten from the older RSA-based Orthros codebase. If you find a security issue please report it in the GitHub issues section, if it is more severe and requires confidentiality please email dylan@suntzusecurity.com to exchange PGP keys.

Under MIT Licensing 
**Please see provided LICENSE file in source for license info**

## Common
All functions will return the same basic formatted response, returned "error" 0 is a successful execution, 1 is unsuccessful;
```json
{
    "result": "some good or bad result", 
    "called": "some_action_name", 
    "error": 0 
}
```

**Note about base64 encoded strings**
For transfer accross POST the characters ```-```, ```/```, ```=``` are replaced with ```-```, ```_```, ```~``` respectively when sending requests with the "application/x-www-form-urlencoded" header. The backend reverses this on request for it's processing use. 

### Request format
All requests must have the GET parameter action filled with a request method, and not all methods require POST input.

## Request methods
### `server_pub`
Query for server's public key

**Required GET params; N/A**
**Required POST params; N/A**
```
https://env1.suntzusecurity.com?action=server_pub
```

Response;
```
{  
   "result":"I271sddOhMFGdfzeBZq32e54gzYra+xR24miCPS\/GTQ=",
   "called":"server_pub",
   "error":0
}
```

---

### `check_key`
Check if a public key exists on the server.

**Required GET params; N/A**
**Required POST; ```user_pub```**

Example endpoint URL; 
```
https://env1.suntzusecurity.com?action=check_key
```

Example POST input;
```
user_pub=wUr_lU-cfrfhOP0495_I-J6grIGOkbJQOzZQb2aXtXs~
```

Response;
```
{
	"result":"public key exists",
	"called":"user_check_public_key",
	"error":0
}
```

---

### `submit_key`
Takes in a public key and an Ed25519 signature of the public key, validates the signature and sets up a new user for the public key

**Required GET params; N/A**
**Required POST; ```user_pub```, ```key_signature```**

Example endpoint URL; 
```
https://env1.suntzusecurity.com?action=submit_key
```

Example POST input;
```
user_pub=Y8bIgMbmeTEkKjwPIo1d3ZGFa-9XeGLArG-lp6agMCw~&key_signature=BcYk2WtF6n9lOhUjbp8lT6exaz5qNgFWh1wuA5wEavBbeI6tBKwMVjLsNjQZGbAAIzuCYoFgfd3d-5StKVcJBg~~
```

Response;
```
{
	"result":"public key written successfully!",
	"called":"user_submit_new_public_key",
	"error":0
}
```

---

### `get_pub`
Takes in user public key and reciever ID, returns pub for ID if exists

**Required GET params; N/A**
**Required POST; ```user_pub```**

Example endpoint URL; 
```
https://env1.suntzusecurity.com?action=get_pub
```

Example POST input;
```
user_pub=Y8bIgMbmeTEkKjwPIo1d3ZGFa-9XeGLArG-lp6agMCw~&reciever_id=1c19e068d1136e5eddd7717a52ddb33b2b7a3cf2ab9f4db746c76d4779ed35d3
```

Response;
```
{
    "pub" = "Y8bIgMbmeTEkKjwPIo1d3ZGFa+9XeGLArG+lp6agMCw=",
    "called" = "user_get_public_key",
    "error" = 0
}
```

---

### `check_messages`
Takes in user public key and checks user directory for queued messages

**Required GET params; N/A**
**Required POST; ```user_pub```**

Example endpoint URL; 
```
https://env1.suntzusecurity.com?action=check_messages
```

Example POST input;
```
user_pub=Y8bIgMbmeTEkKjwPIo1d3ZGFa-9XeGLArG-lp6agMCw~
```

Response w/ messages;
```
{
	"msgs":["bd9c80b69919044","91c24ff3eeca662"],
	"called":"user_check_queue",
	"error":0
}
```

Response w/ no messages;
```
{
	"result":"no messages found in queue",
	"called":"user_check_queue",
	"error":1
}
```

---

### `message_send`
Takes in params, if reciever exists create a message package w/ metadata and store the package in their queue. 

**Required GET params; N/A**
**Required POST; ```user_pub```, ```reciever_id```, ```message_signature```, ```message_data```**

Example endpoint URL; 
```
https://env1.suntzusecurity.com?action=message_send
```

Example POST input;
```
user_pub=Y8bIgMbmeTEkKjwPIo1d3ZGFa-9XeGLArG-lp6agMCw~&reciever_id=1c19e068d1136e5eddd7717a52ddb33b2b7a3cf2ab9f4db746c76d4779ed35d3&message_signature=X4BQtaUqDXbhjZdN4lzjmPYhY3xQ3EVrPrKX71_BSVdXzKOjsZ9eXdYdNSnP_arq4vyQQ_AggYH0LjNh38lzCQ~~&message_data=D7Ek3RXD92-3iz7E4lU_aw~~
```

Response;
```
{
	"result":"message written successfully!",
	"called":"user_send_message",
	"error":0
}
```

---

### `message_read`
Takes in params, if message exists grab the package and return response

**Required GET params; N/A**
**Required POST; ```user_pub```, ```message_id```**

Example endpoint URL; 
```
https://env1.suntzusecurity.com?action=message_read
```

Example POST input;
```
user_pub=Y8bIgMbmeTEkKjwPIo1d3ZGFa-9XeGLArG-lp6agMCw~&message_id=0edad589a76334d
```

Response;
```
{
  "package": {
    "message_signature": "X4BQtaUqDXbhjZdN4lzjmPYhY3xQ3EVrPrKX71\/BSVdXzKOjsZ9eXdYdNSnP\/arq4vyQQ\/AggYH0LjNh38lzCQ==",
    "message_data": "D7Ek3RXD92-3iz7E4lU_aw~~\n",
    "sender": "1c19e068d1136e5eddd7717a52ddb33b2b7a3cf2ab9f4db746c76d4779ed35d3",
    "timestamp": 1480407957,
    "message_id": "0edad589a76334d"
  },
  "called": "user_read_message",
  "error": 0
}
```

---

### `message_delete`
Takes in params, if message exists and signature is valid, remove the message from the users queue.

The signature is a SHA256 hash of the message ID signed with Ed25519.

**Required GET params; N/A**
**Required POST; ```user_pub```, ```message_id```, ```signature```**

Example endpoint URL; 
```
https://env1.suntzusecurity.com?action=message_delete
```

Example POST input;
```
user_pub=Y8bIgMbmeTEkKjwPIo1d3ZGFa-9XeGLArG-lp6agMCw~&message_id=0edad589a76334d&signature=2IKmijO9u9kOQS_mJOR-Db8i5cAigc2nJN6GBjTBxy39fZMR-nc_ek7QInigvbBP-nMUZlw09ukgq0IeLInJAw~~
```

Response;
```
{
  "result": "message deleted!",
  "called": "user_delete_message",
  "error": 0
}
```

---
