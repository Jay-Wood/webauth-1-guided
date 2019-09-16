const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require("bcryptjs");

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let {username, password} = req.body;
  const hash = bcrypt.hashSync(password, 12)

  Users.add({username, password: hash})
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;
  let hashedPassword = bcrypt.hashSync(password, 12)

  // const Auth = bcrypt.compareSync(password, hashedPassword);
  // console.log("Auth: ", Auth)

  Users.findBy({ username })
    .first()
    .then(user => {
      //check passwor here:
      // bcrypt.compareSync(password, user.password)

      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.get("/hash", (req, res) => {
  const name = req.query.name;
  console.log(req.query)

  //hash the name async:
  // const hash = bcrypt.hash(name, 12, function(err, hash) {
  //   res.send(`the hash for ${name} is ${hash}`)
  // })

  //same as above ex with "hash", but not async
  const hash2 = bcrypt.hashSync(name, 12);
  res.send(`the hash for ${name} is ${hash2}`);
})

function restricted(req, res, next) {
  const { username, password } = req.headers;

  if(username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        if(user && bcrypt.compareSync(password, user.password)) {
          next()
        } else {
          res.status(401).json({message: "Invalid Creds"})
        }
      })
      .catch(error => {
        res.status(500).json({ message: 'Unexpected error' });
      })
  } else {
    res.status(400).json({ message: "No creds provided." })
  }
}


const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
