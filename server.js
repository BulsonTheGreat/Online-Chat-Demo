const express = require("express");
const path = require("path");
const crypto = require('crypto');
const app = express();
const server = require("http").createServer(app);

const users = {};

let sharedKey;
let sentMessage;

const io = require("socket.io")(server);

app.use(express.static(path.join(__dirname+"/public")));

io.on("connection", function(socket){
	socket.on("newuser",function(username){
    // Generate Alice's public and private keys using ECDH
    const aliceUsername = username;
    const alice = crypto.createECDH('secp256k1');
    alice.generateKeys();
    const alicePublicKey = alice.getPublicKey().toString('base64');

    // Store Alice's public key in users object
    users[aliceUsername] = { publicKey: alicePublicKey };
    console.log(users);

    const usernames = Object.keys(users);
    if (usernames.length >= 2) {
      // If there are two or more users, establish a shared secret key using ECDH
      const bob = getOtherUser(aliceUsername);
      const bobPublicKey = users[bob].publicKey;
      sharedKey = alice.computeSecret(bobPublicKey, 'base64', 'hex');
      console.log("shared key: " + sharedKey);
    }
    
    socket.broadcast.emit("update", username + " joined the conversation");
	});

	socket.on("exituser",function(username){
		socket.broadcast.emit("update", username + " left the conversation");
    delete users[username];
    console.log(users);
	});

	socket.on("chat",function(data){
    // Encrypt the message using the shared key
    sentMessage = encryptMessage(data.text);

    // Decrypt the received message using the shared key
    const receivedMessage = decryptMessage(sentMessage);
    data.text = receivedMessage;

    // Broadcast the decrypted message to other clients
		socket.broadcast.emit("chat", data);
	});
});

function encryptMessage(message){
  console.log("Sent message: " + message);
  // Generate a random initialization vector (IV)
  const IV = crypto.randomBytes(16);

  // Create a cipher using AES-256-GCM algorithm and the shared key
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(sharedKey, 'hex'), IV);

  // Encrypt the message using UTF-8 encoding
  let encrypted = cipher.update(message, 'utf-8', 'hex');
  // Finalize encryption and append the final block of encrypted data to the 'encrypted' variable
  encrypted += cipher.final('hex');

  // Get the authentication tag
  const authTag = cipher.getAuthTag().toString('hex');

  // Combine IV, encrypted message, and authentication tag into a payload
  const payload = IV.toString('hex') + encrypted + authTag;

  // Convert the payload to base64 for transmission
  const payload64 = Buffer.from(payload, 'hex').toString('base64');
  console.log("Encrypted message: " + payload64);
  return payload64;
}

function decryptMessage(payload64){
  // Convert the base64 payload to hex
  const bob_payload = Buffer.from(payload64, 'base64').toString('hex');
  console.log("Received message: " + bob_payload);

  // Extract IV, encrypted message, and authentication tag from the payload
  const bob_iv = bob_payload.substring(0, 32);
  const bob_encrypted = bob_payload.substring(32, bob_payload.length - 32);
  const bob_authTag = bob_payload.substring(bob_payload.length - 32);

  try{
      // Create a decipher using AES-256-GCM algorithm, shared key, and IV
      const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(sharedKey, 'hex'), Buffer.from(bob_iv, 'hex'));

      // Set the authentication tag
      decipher.setAuthTag(Buffer.from(bob_authTag, 'hex'));

      // Decrypt the message and convert it to UTF-8 encoding
      let decryptedMessage = decipher.update(bob_encrypted, 'hex', 'utf-8');
      decryptedMessage += decipher.final('utf-8');
      console.log("decrypted message: " + decryptedMessage)
      return decryptedMessage;

  } catch(error){
      console.log(error.message);
  }
}

function getOtherUser(username) {
  const usernames = Object.keys(users);
  const otherUsername = usernames.find(user => user !== username);
  return otherUsername;
}

server.listen(5000);
