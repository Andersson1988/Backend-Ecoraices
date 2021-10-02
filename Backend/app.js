const SIGNING_KEY = 'oqLlmSRa5j3Y8YEYRsYrgO9ubTS2wv/ENuMCpm5HX555ef4aRPkceYru1lTuvccXm1dT73QuU3nqB5aRzq4nDVKpFSQs3oXvFSEEk2XNt2RPgMPTDWPU2h3Fblc5nDxLJHKRqsXDgncc/8aOXmGrMp2+SruMuz3NTFUf0YlyB+Fwb8z+hnK7JN4uszxO//72d4tcrs0xbuv4ke+2WXUN5ROu4/2nky0eJUP38/VH41jifprI0EHfrrt2aY3O9FvH5vFWT2NHmPJBz7ZVl6zoKB4ja1D03ZklOD/zJuYTNRUBo+2zaHyjmmvOFkvG3NiCtlguIM0tpgwV468eM2KKTQ==';
var express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
var mysql = require('mysql');
const nJwt = require('njwt');
const jwt= require("jsonwebtoken");

var app = express()
.use(cors({credentials: true, origin: 'http://localhost:4200'
}))
.use(bodyParser.urlencoded({extended: true}))
.use(bodyParser.json());

app.post('/registro', function (req, res) {
    const connection = mysql.createConnection({
      host     : 'localhost',
      user     : 'root',
      password : 'andersson',
      database : 'ecoraices'
    });
    connection.connect((err) => {
      if(err) throw err;
      //console.log('Connected to MySQL Server!');
    });

    var idusuario = req.body.idusuario;
    var usuario = req.body.usuario;
    var nombres = req.body.nombres;
    var apellidos = req.body.apellidos;
    var email = req.body.email;
    var password = req.body.password;
    let hashPass = bcrypt.hashSync(password, 8);
  
    let insert = 'INSERT INTO usuarios (idusuario,usuario,nombre,apellido,email,password) VALUES(?,?,?,?,?,?)';   
    let query = mysql.format(insert,[idusuario,usuario,nombres,apellidos,email,hashPass]);
    connection.query(query, (err, result) => {
      if(err) throw err;
      console.log('Insert email: ok');
      connection.end();
    });
  
    return res.status(201).json({
            "Status": "ok registrado", 
            "reg": true,
            "usuario": usuario,
            "email": email,
            "password": password
            });
  });

  app.post('/login', function (req, res) {
    const connection = mysql.createConnection({
      host     : 'localhost',
      user     : 'root',
      password : 'andersson',
      database : 'ecoraices'
    });
    connection.connect((err) => {
      if(err) throw err;
      //console.log('Connected to MySQL Server!');
  });

  var email = req.body.email;
  var password = req.body.password;


  let select = 'SELECT email, password,idusuario FROM usuarios WHERE email=?';
  let query = mysql.format(select,[email]);
  connection.query(query, (err, result) => {
    if(err) throw err;
    console.log("---------- ", result);
    
    if (result == 0) {
      return res.status(401).send({ status: 'authentication failed', auth: false});
    };
    
    if (!bcrypt.compareSync(password, result[0].password)) {
      return res.status(401).send({ status: 'authentication failed', auth: false}
      );
    };

    connection.end();

    let jwt = nJwt.create({ email:email, idusuario: result[0].idusuario }, SIGNING_KEY);
    jwt.setExpiration(new Date().getTime() + (1 * 60 * 1000));
    let token = jwt.compact();

    return res.status(200).json({
      "Status": "authentication ok",
      token: token
    });
  });
});  

app.get('/perfil', function (req, res) {
  
  if (!req.header('Authorization')) {
    return res.status(403).send({ auth: false, message: 'No token provided' });
  }
  let sub = req.header('Authorization').split(' ')
  let token = sub[1];
  nJwt.verify(token, SIGNING_KEY, function(err, decoded) {
    if (err) {
      return res.status(403).send({ auth: false, message: err });
    }

    //idUser = decoded.body.id;
    email = decoded.body.email;

    const connection = mysql.createConnection({
      host     : 'localhost',
      user     : 'root',
      password : 'andersson',
      database : 'ecoraices'
    });
    connection.connect((err) => {
      if(err) throw err;
      //console.log('Connected to MySQL Server!');
    });

    let select = 'SELECT password FROM usuarios WHERE email=?';   
    let query = mysql.format(select,[email]);
    connection.query(query, (err, result) => {
      if(err) throw err;

      connection.end();

      return res.status(200).json({
        "Status": "Token ok",
        email: email,
        password: result[0].password
      });
    });

  });
});

app.listen(10107, function () {
    console.log('Example app listening on port 10107!');
  });

  