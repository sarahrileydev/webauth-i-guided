const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const db = require("./database/dbConfig.js");
const Users = require("./users/users-model.js");

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get("/", (req, res) => {
  res.send("It's alive!");
});

server.post("/api/register", (req, res) => {
  let user = req.body; //user contains plain text password
  //generate a hash of the user's password, we'll do it synchronously, no need for async
  const hash = bcrypt.hashSync(user.password, 10); // plain text password and number represents how many times we will hash it  2 to the 10th rounds, set to at least 12
  // user might not like it if it takes too long
  //over ride user.password with hashed version
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post("/api/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      //update the if condition to check if the passwords match
      if (user && bcrypt.compareSync(password, user.password)) {
        //compareSync checks the hashed version
        res.status(200).json({ message: `Welcome ${user.username}!` });
        // if (user) {
        //   res.status(200).json({ message: `Welcome ${user.username}!` });
        // } else {
        //   res.status(401).json({ message: "Invalid Credentials" });
        // }
      }else{
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get("/api/users", (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
