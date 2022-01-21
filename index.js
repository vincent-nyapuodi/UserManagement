const express = require('express');
const bodyParser = require("body-parser");
const path = require('path');
const mysql = require("mysql");
const axios = require('axios');
const expressSession = require('express-session')
const NodeRSA = require('node-rsa');


const app = express();

//database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'login-node',
    port: 3307
});

db.connect((error) => {
    if (error){
        console.log(error);
    }else{
        console.log("MYSQL connected successful...")
    }
})


let key_private = '';

generateKeys();

 function generateKeys(){
    const key = new NodeRSA({b: 512});

    var private_key = key.exportKey('private');
        // console.log(private_key);
        key_private = private_key

    var public_key = key.exportKey('public');
        // console.log(public_key)

//forward public key to client app
    axios
    .post('http://localhost:4000/storeKeys', {
    publicKey: public_key
  })
  .then(response => {
    //No response expected
  })
  .catch(error => {
    console.error(error)
  })}



app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(bodyParser.json());

app.use(expressSession({secret:'Keep it secret'
,name:'uniqueSessionID'
,saveUninitialized:false}))

app.set('views', path.join(__dirname))
app.set('view engine', '.hbs');




//authenticate endpoint
app.post("/authenticate", (req, res) => {
    const encryptedStringGetway = req.body.encryptedString
    // console.log(encryptedStringGetway);
   
    let privateKey = new NodeRSA(key_private);

    // Use private key to decrypt req.body
    const decryptedString = JSON.parse(privateKey.decrypt(encryptedStringGetway, 'utf8'));
    // console.log(decryptedString);


    const {email, password} = decryptedString;
    
    if (email && password) {
		db.query(
            'SELECT * FROM users WHERE email = ? AND password = ?', [email, password], 
            (error, results, fields) => {
                console.log(results)
                
			if (results.length > 0) {
				req.session.loggedIn = true;
				req.session.email = email;
                console.log("success");
                const response = {
                    "statusCode": 200,
                    "statusMessage": "Successfully fetched user details",
                    "body": JSON.stringify(results)
                }
                res.send(response);
			} else {
                req.session.loggedIn = false;
				req.session.email = email;
                console.log("not successful");
                const response = {
                    "statusCode": 401,
                    "statusMessage": "User not found",
                    "body": null
                }
                res.send(response);

			}			
			res.end();
		});
	} else {
		res.send('Please enter Email and Password!');
		res.end();
	}
});


app.listen(4001, () => {
    console.log("Server started on port 4001")
})