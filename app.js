const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const bodyParser = require('body-parser');
const fs = require('fs');
const session = require('express-session');
const path = require('path');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const xssFilter = require('./private/middleware/filterXSS');
const bcrypt = require('bcrypt');

const limiter = rateLimit({
  windowMs: 500, 
  max: 20, 
  message: "Prea multe cereri, asteptati..."
});
const { body, validationResult } = require('express-validator');

app.use(limiter);
const port = 6789;
const accessLogStream = fs.createWriteStream(
    path.join(__dirname, 'access.log'),
    { flags: 'a' }
);


app.use(morgan('combined', { stream: accessLogStream }));


var utilizatori = [];
fs.readFile('utilizatori.json', (err, data) => {
    if(err) throw err;
    utilizatori = JSON.parse(data);
});


const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "public/imagini/produse/all/");
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
        const ext = path.extname(file.originalname);
        cb(null, file.fieldname + "-" + uniqueSuffix + ext);
    }
});

const upload = multer({ 
    storage,
    fileFilter: (req, file, cb) => {
        if (!file.mimetype.startsWith('image/')) {
            return cb(new Error('Fisierul nu este o imagine!'), false);
        }
        cb(null, true);
    }
 });

const ipBlacklist = new Map();
const BLOCK_DURATION_MS = 10000; // 10 secunde
const MAX_FAILED_ATTEMPTS = 3;

const conectariEsuate = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const BLOCK_TIME_MS = 10000; // 10 secunde


app.set('view engine', 'ejs');
app.use(expressLayouts);
app.use('/public', express.static(path.join(__dirname, 'public')));
app.set('layout', 'layout');
app.use(session({
    secret: 'secret-mega-important',
    resave: false,
    saveUninitialized: true
}));
app.use((req, res, next) => {
    res.locals.utilizator = req.session.utilizator || null;
    next();
});
app.use(express.static('public'))
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(xssFilter);

app.use((req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    if(ipBlacklist.has(ip)) {
        const data = ipBlacklist.get(ip);
        if(data.blockedUntil && now < data.blockedUntil) {
            return res.status(403).send(`
                    <div style="width: 100vw; display: flex; justify-content: center; align-iterms: center; flex-direction: column;">
                        <h3>Acces temporar blocat din cauza incercarilor repetate de accesare a resurselor inexistente.</h3>
                        <a href="/">Home</a>
                    </div>    
                    `);
        } else if (data.blockedUntil && now >= data.blockedUntil) {
            ipBlacklist.delete(ip);
        }
    }
    if(conectariEsuate.has(ip) && req.path === '/autentificare') {
        const data = conectariEsuate.get(ip);
        if(data.blockedUntil && now < data.blockedUntil) {
            return res.status(403).send(`
                    <div style="width: 100vw; display: flex; justify-content: center; align-iterms: center; flex-direction: column;">
                        <h3>Acces temporar blocat din cauza incercarilor esuate de conectare.</h3><br>
                        <a href="/">Home</a>
                    </div>    
                    `);
        } else if (data.blockedUntil && now >= data.blockedUntil) {
            conectariEsuate.delete(ip);
        }
    }
    res.locals.mesajEroareText = req.session.mesajEroareText || null;
    res.locals.mesajSuccess = req.session.mesajSuccess || null;

    if (req.session.mesajSuccess) {
        delete req.session.mesajSuccess;
    }
    if(req.session.mesajEroareText) {
        delete req.session.mesajEroareText;
    }

    if(res.locals.mesajEroareText === "Contul/IP-ul este blocat temporar. Incearca mai tarziu.") {
        if(req.path === '/autentificare') {
            return res.redirect('/restrictie');
        }
    }

    next();
});

app.get('/restrictie', (req, res) => {
    res.send('Acces restrictionat. Contul/IP-ul este blocat temporar.');
});

app.get('/', (req, res) => {
    const username = req.cookies.username;
    const utilizator = req.session.utilizator || null;
    const mesajSuccess = req.session.mesajSuccess || null;
    const mesajEroareText = req.session.mesajEroare || null;
    req.session.mesajSuccess = null;
    req.session.mesajEroareText = null;

    const filePath = path.join(__dirname, 'private/database/cumparaturi.db');
    fs.access(filePath, fs.constants.F_OK, (err) => {
        if(err) {
            produse = null;
            res.render('index', { utilizator, mesajSuccess, mesajEroareText, produse });
        } else {
            const db = new sqlite3.Database('private/database/cumparaturi.db', (err) => {
            if (err) {
                console.error("Eroare la conectarea la baza de date:", err);
                return res.render('index', { utilizator, mesajSuccess, produse: [] });
            }
            });
            db.all("SELECT * FROM produse", [], (err, rows) => {
                if (err) {
                    console.error("Eroare la citirea produselor:", err);
                    return res.render('index', { utilizator, mesajSuccess, produse: [] });
                }

                res.render('index', { utilizator, mesajSuccess, produse: rows });
                db.close();
            });
        }
    });

});

// async
var listaIntrebari = [];
fs.readFile('intrebari.json', (err, data) => {
    if(err) throw err;
    listaIntrebari = JSON.parse(data);
});
app.post('/inserare-produs', upload.single('inserare-imagine'), xssFilter, (req, res) => {
    const utilizator = req.session.utilizator || null;
    if(utilizator) {
        if(utilizator.rol) {
            const { 'inserare-nume': nume, 'inserare-cantitate': cantitate, 'inserare-pret': pret } = req.body;
            
            if(!req.file) {
                req.session.mesajEroareText = "Fisierul nu a fost incarcat.";
                console.error('Eroare. Nu s-a incarcat fisierul.');
                return res.redirect('/admin');
            }
            const imagine = `/public/imagini/produse/all/${req.file.filename}`;

            const db = new sqlite3.Database('private/database/cumparaturi.db', (err) => {
                console.log('Conectat la BD pentru inserare produs.');
                if(err) {
                    console.error("Eroare la conectarea la baza de date (inserare): ", err);
                    return res.status(500).send('Eroare la conectarea la baza de date (inserare).');
                }
            });

            db.run(
                `INSERT INTO produse (nume, imagine, cantitate, pret) VALUES (?, ?, ?, ?)`,
                [nume, imagine, parseInt(cantitate), parseFloat(pret)],
                (err) => {
                    if(err) {
                        console.error('Eroare la inserarea produsului: ', err);
                        return res.status(500).send("Eroare la inserarea produsului.");
                    }

                    req.session.mesajSuccess = "Produsul a fost adaugat cu succes!";
                    db.close((err) => {
                        if (err) console.error("Eroare la inchiderea bazei de date: ", err);
                        res.redirect('/admin');
                    });
                }
            );
        }
    }
    
});

app.post("/upload", upload.single("inserare-imagine"), (req, res) => {
    const utilizator = req.session.utilizator || null;
    if(utilizator) {
        if(utilizator.rol) {
            console.log("Fisier primit:", req.file);
            res.json({ message: "Imagine incarcata cu succes!", file: req.file });
        }
    }
});

app.get('/admin', (req, res) => {
    const utilizator = req.session.utilizator || null;
    res.render('admin', { utilizator });
});

app.get('/chestionar/:index', (req, res) => {
    const index = parseInt(req.params.index);
    if(index >= listaIntrebari.length) {
        res.redirect('/rezultat-chestionar');
        return;
    }
    res.render('chestionar', {
        intrebare: listaIntrebari[index],
        index,
        total: listaIntrebari.length
    });
});

app.post('/chestionar/:index', (req, res) => {
    const index = parseInt(req.params.index);
    if(!req.session.raspunsuri) req.session.raspunsuri = [];

    req.session.raspunsuri[index] = parseInt(req.body.raspuns);

    res.redirect(`/chestionar/${index + 1}`);
});

app.get('/rezultat-chestionar', (req, res) => {
    const raspunsuri = req.session.raspunsuri || [];
    let scor = 0;

    const corectitudine = listaIntrebari.map((intrebare, index) => {
        const userAnswer = raspunsuri[index];
        const corect = userAnswer === intrebare.corect;
        if (corect) scor++;

        return {
            intrebare: intrebare.intrebare,
            corect,
            raspunsUser: intrebare.variante[userAnswer],
            raspunsCorect: intrebare.variante[intrebare.corect]
        };
    });

    res.render('rezultat-chestionar', { scor, total: listaIntrebari.length, raspunsuri: corectitudine });
});

app.get('/autentificare', (req, res) => {
    const mesajEroare = req.cookies.mesajEroare || null;
    const mesajEroareText = req.session.mesajEroareText || null;
    const mesajSuccess = req.session.mesajSuccess || null;
    res.clearCookie('mesajEroare');

    res.render('autentificare', { mesajEroare, mesajEroareText, mesajSuccess });
});

app.post('/verificare-autentificare', async (req, res) => { 
        const username = req.body['autentificare-username'] ? req.body['autentificare-username'] : "";
        const password = req.body['autentificare-password'] || "";
        const ip = req.ip;
        const now = Date.now();
        const record = conectariEsuate.get(ip) || { count: 0, blockedUntil: null };

        if(record.blockedUntil && now < record.blockedUntil) {
            req.session.mesajEroareText = "Contul/IP-ul este blocat temporar. Incearca mai tarziu.";
            const mesajEroareText = req.session.mesajEroareText;
            const mesajSuccess = req.session.mesajSuccess;
            return res.redirect('/autentificare');
        }

        const utilizator = utilizatori.find(u => u.username === username);
        if(utilizator) {
            const parolaCorecta = await bcrypt.compare(password, utilizator.password);
            if(parolaCorecta) {
                conectariEsuate.delete(ip);
                res.cookie('username', username, {
                    expires: new Date(Date.now() + 10000)
                });
                const nume = utilizator.nume;
                const prenume = utilizator.prenume;
                const rol = utilizator.rol;
                req.session.utilizator = { username, nume, prenume, rol };
                res.clearCookie('mesajEroare');
                res.redirect('/');
            }
        } else {
            record.count += 1;
            if(record.count >= MAX_LOGIN_ATTEMPTS) {
                record.blockedUntil = now + BLOCK_TIME_MS;
                console.warn(`Blocare temporara: ${ip}`);
            }
            conectariEsuate.set(ip, record);
            res.cookie('mesajEroare', 'Date incorecte', { path: '/autentificare', maxAge: 3000 });
            res.redirect('/autentificare');
        }
});

app.get('/logout', (req, res) => {
    req.session.utilizator = null;
    res.clearCookie('username');
    res.redirect('/');
});

app.get('/creare-bd', (req, res) => {
    const utilizator = req.session.utilizator || null;
    if(utilizator) {
        if(utilizator.rol === "admin") {
            const db = new sqlite3.Database('private/database/cumparaturi.db', (err) => {
                    if (err) {
                        console.error("Eroare la conectarea la baza dee date: ", err);
                        return res.status(500).send("Eroare la conectarea la baza de date");
                    }

                    console.log("Conectat la baza de date SQLite.");
                });

                db.serialize(() => {
                    db.run(`CREATE TABLE IF NOT EXISTS produse (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        nume TEXT NOT NULL,
                        imagine TEXT NOT NULL,
                        cantitate INTEGER NOT NULL,
                        pret REAL NOT NULL
                    );`), (err) => {
                            if(err) {
                                console.error("Eroare la crearea tabelului: ", err);
                                return res.status(500).send("Eroare la crearea tabelului");
                            }
                            console.log("Tabelul 'cumparaturi' a fost creat sau exista deja.")
                        }
                });
                exists_db = true;

                db.close((err) => {
                    if(err) {
                        console.error("Eroare la inchiderea bazei de date: ", err);
                        return res.status(500).send("Eroare la inchiderea bazei de date");
                    }
                    console.log("Baza de date inchisa.");

                    req.session.mesajSuccess = "Baza de date a fost creata cu succes!";
                    res.redirect("/admin");
                });
        }
    }
});

app.get('/inserare-bd', (req, res) => {
    res.render('inserare-bd');
});

app.post('/inserare-bd', (req, res) => {
    const utilizator = req.session.utilizator || null;
    if(utilizator) {
            if(utilizator.rol === "admin") {
                const produse = [
                        { nume: "Sculptura de lemn", imagine: "/public/imagini/produse/sculptura/sculptura_1.jpg", cantitate: 10, pret: 2500.50 },
                        { nume: "Sculptura leu", imagine: "/public/imagini/produse/sculptura/sculptura_2.jpeg", cantitate: 23, pret: 1500.75 },
                        { nume: "Sculptura trib", imagine: "/public/imagini/produse/sculptura/sculptura_3.jpg", cantitate: 2, pret: 3600.29 },        
                        { nume: "Sculptura Omul pe Cal", imagine: "/public/imagini/produse/sculptura/sculptura_4.jpeg", cantitate: 1, pret: 3600.29 },        
                        { nume: "Culoarea din viata", imagine: "/public/imagini/produse/panza/panza_1.jpeg", cantitate: 5, pret: 3600.29 },        
                        { nume: "Mysterious fog", imagine: "/public/imagini/produse/panza/panza_2.jpg", cantitate: 8, pret: 3600.29 },        
                        { nume: "Venezia", imagine: "/public/imagini/produse/panza/panza_3.jpg", cantitate: 12, pret: 3600.29 },        
                        { nume: "Copacul", imagine: "/public/imagini/produse/panza/panza_4.jpeg", cantitate: 27, pret: 3600.29 },       
                    ];

                    const db = new sqlite3.Database('private/database/cumparaturi.db', (err) => {
                        if(err) {
                            console.error("Eroare la conectarea la baza de date: ", err);
                            return res.status(500).send("Eroare la conectarea la baza de date");
                        }
                    });

                    db.serialize(() => {
                        const stmt = db.prepare("INSERT INTO produse (nume, imagine, cantitate, pret) VALUES (?, ?, ?, ?)");
                        produse.forEach((produs) => {
                            stmt.run(produs.nume, produs.imagine, produs.cantitate, produs.pret, (err) => {
                                if(err) {
                                    console.error("Eroare la inserarea produsului: ", err);
                                }
                            });
                        });
                        stmt.finalize();
                    });
                    db.close((err) => {
                        if(err) {
                            console.error("Eroare la inchiderea bazei de date: ", err);
                            return res.status(500).send("Eroare la inchiderea bazei de date");
                        }
                        console.log("Baza de date inchisa.");
                        req.session.mesajSuccess = "Produsele au fost adaugate in baza de date!";
                        res.redirect("/admin");
                    });
            }
    }
});

app.post('/adaugare-cos', (req, res) => {
    const idProdus = req.body.id;
    if(!req.session.cos) req.session.cos = []
    req.session.cos.push(idProdus);
    res.redirect('/');
});

app.get('/vizualizare-cos', (req, res) => {
    const cos = req.session.cos || [];
    const db = new sqlite3.Database('private/database/cumparaturi.db', (err) => {
        if(err) {
            console.error("Eroare la conectarea la baza de date: ", err);
            return res.status(500).send("Eroare la conectarea la baza de date");
        }
        console.log("Conectat la baza de date SQLite.");
    });

    if (cos.length === 0) {
        return res.render('vizualizare-cos', { produse: [] });
    }

    const placeholder = cos.map(() => '?').join(',');

    const query = `SELECT * FROM produse WHERE id IN (${placeholder})`;
    db.all(query, cos, (err, rows) => {
        if(err) {
            console.error("Eroare la interogarea bazei de date: ", err);
            return res.status(500).send("Eroare la interogarea bazei de date.");
        }
        res.render('vizualizare-cos', { produse: rows });
    });
    
    db.close((err) => {
        if (err) {
            console.error("Eroare la inchiderea bazei de date:", err);
            return res.status(500).send("Eroare la inchiderea bazei de date");
        }
        console.log("Baza de date inchisa.");
    });
});

app.post('/stergere-element', (req, res) => {
    const idSters = req.body.id;
    if(!req.session.cos) req.session.cos = [];

    req.session.cos = req.session.cos.filter(id => id !== idSters);

    res.redirect('/vizualizare-cos');
});

app.get('/sterge-date', (req, res) => {
    const utilizator = req.session.utilizator || null;
    if(utilizator) {
        if(utilizator.rol === "admin") {
            const dbPath = 'private/database/cumparaturi.db';
            const db = new sqlite3.Database(dbPath, (err) => {
                if (err) {
                    console.error("Eroare la conectarea la baza de date: ", err);
                    return res.status(500).send("Eroare la conectarea la baza de date");
                }
                console.log("Conectat la baza de date SQLite.");
            });

            db.all(`SELECT imagine FROM produse`, [], (err, rows) => {
                if (err) {
                    console.error("Eroare la extragerea imaginilor: ", err);
                } else {
                    rows.forEach(row => {
                        const imgPath = row.imagine.replace('/public', 'public');
                        if(imgPath.startsWith('public/imagini/produse/all/')) {
                            const absolutePath = path.join(__dirname, imgPath);
                            fs.unlink(absolutePath, (err) => {
                                if (err) {
                                    console.error("Eroare la stergerea fisierului", absolutePath, ":", err);
                                } else {
                                    console.log("Fisier sters:", absolutePath);
                                }
                            });
                        }
                    });
                }

                db.run(`DELETE FROM produse`, (err) => {
                    if (err) {
                        console.error("Eroare la stergerea datelor din tabel: ", err);
                        return res.status(500).send("Eroare la stergerea datelor din tabel");
                    }
                    console.log("Toate datele au fost sterse din tabelul 'produse'.");
                });

                db.close((err) => {
                    if (err) {
                        console.error("Eroare la inchiderea bazei de date: ", err);
                        return res.status(500).send("Eroare la inchiderea bazei de date");
                    }
                    console.log("Conexiunea a fost inchisa.");
                    exists_db = false;
                    req.session.mesajSuccess = "Toate datele au fost sterse din tabel si imaginile au fost sterse!";
                    res.redirect("/admin");
                });
            });
        }
    }
});

app.use((req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    if(ipBlacklist.has(ip)) {
        const data = ipBlacklist.get(ip);
        if(data.blockedUntil && now < data.blockedUntil) {
            return res.status(403).send(`
                    <div style="display: flex; justify-content: center; align-iterms: center;">
                        <h3>Acces temporar blocat din cauza incercarilor repetate de accesare a resurselor inexistente.</h3>
                    </div>    
                    `);
        } else if (data.blockedUntil && now >= data.blockedUntil) {
            ipBlacklist.delete(ip);
        }
    }

    const data = ipBlacklist.get(ip) || { attempts: 0, blockedUntil: null };
    data.attempts += 1;

    if(data.attempts >= MAX_FAILED_ATTEMPTS) {
        data.blockedUntil = now + BLOCK_DURATION_MS;
        console.warn(`IP-ul ${ip} a fost blocat temporar.`);
    }
    ipBlacklist.set(ip, data);

    res.status(404).render('404', { ip });
});

app.listen(port, () => console.log(`Serverul rulează la adresa http://localhost:${port}/`));