const fs = require('fs');
const bcrypt = require('bcrypt');

const users = [];

bcrypt.hash('matei', 10, (err, hashMatei) => {
    if (err) throw err;

    users.push({
        username: 'matei',
        nume: 'Matei',
        prenume: 'Andrei',
        password: hashMatei,
        rol: 'admin'
    });

    bcrypt.hash('andrei', 10, (err, hashAndrei) => {
        if (err) throw err;

        users.push({
            username: 'andrei',
            nume: 'Popescu',
            prenume: 'Andrei',
            password: hashAndrei,
            rol: 'user'
        });

        fs.writeFile('utilizatori.json', JSON.stringify(users, null, 2), (err) => {
            if (err) throw err;
            console.log('S-au creat utilizatorii.');
        });
    });
});
