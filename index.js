const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const bcrypt = require('bcryptjs');

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');
const restricted = require('./auth/restricted-middleware.js');
const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
    res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
    let user = req.body;

    const hash = bcrypt.hashSync(user.password, 8);

    user.password = hash;

    Users.add(user)
        .then(saved => {
            res.status(201).json(saved);
        })
        .catch(error => {
            res.status(500).json(error);
        });
});

server.post('/api/login', (req, res) => {
    let { username, password } = req.body;
    if (username && password) {
        Users.findBy({ username })
            .first()
            .then(user => {
                if (user && bcrypt.compareSync(password, user.password)) {
                    res.status(200).json({ message: `Welcome ${user.username}!` });
                } else {
                    res.status(401).json({ message: 'Invalid Credentials' });
                }
            })
            .catch(error => {
                res.status(500).json(error);
            });
    } else {
        res.status(500).json({ message: 'please provide credentials' });
    };
});

server.get('/api/users', (req, res) => {
    Users.find()
        .then(users => {
            res.json(users);
        })
        .catch(err => res.send(err));
});

server.get('api/theusers', restricted, (req, res) => {
    Users.find()
        .then(theUsers => {
            res.json(users);
        })
        .catch(error => {
            res.send(err);
        });
});



//during lecture
server.get('/hash', (req, res) => {
    const password = req.headers.authorization;
    // read a password from the Authorization header
    if (password) {
        //that 8 is how we slow down hackers trying to pregenerate hackers
        const hash = bcrypt.hashSync(password, 10) //number of rounds hashing takes to  2^8 times
            //a good starting value is 14 - if get a lot of logins happening may need this to async

        res.status(200).json({ hash });


        // return an object with the password hashed using bcryptjs
        // { hash: '970(&(:OHKJHIY*HJKH(*^)*&YLKJBLKJGHIUGH(*P' }
    } else {
        res.status(500).json({ message: 'gerrr' });
    }
});



const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));