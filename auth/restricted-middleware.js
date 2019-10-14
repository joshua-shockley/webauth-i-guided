const bcrypt = require('bcryptjs');

const Users = require('../users/users-model.js');

module.exports = function restricted(req, res, next) {
    const { username, password } = req.headers; //using header since a get and cant use a body go pull the info for comparison

    if (username && password) {
        //borrowed validation from login to use for accessing this user get...
        Users.findBy({ username })
            .first()
            .then(user => {
                if (user && bcrypt.compareSync(password, user.password)) {
                    // res.status(200).json({ message: `Welcome ${user.username}!` });
                    next();
                } else {
                    res.status(401).json({ message: 'Invalid Credentials' });
                }
            })
            .catch(error => {
                res.status(500).json(error);
            });

    } else {
        res.status(400).json({ message: 'please provide valid credentials!!!' });
    }
}