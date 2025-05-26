const fs = require('fs');
const path = require('path');

function stergePoze(numeFisier) {
    const folderPath = path.join(__dirname, '../../public/imagini/produse/all');
    const filePath = path.join(folderPath, numeFisier);

    if (fs.existsSync(filePath)) {
        fs.unlink(filePath, (err) => {
            if (err) {
                console.error("Eroare la ștergerea fișierului:", err);
            } else {
                console.log("Fișierul șters:", numeFisier);
            }
        });
    } else {
        console.log("Fișierul nu a fost găsit pentru ștergere:", numeFisier);
    }
}

function xssFilter(req, res, next) {
    let gasit = false;
    if(req.originalUrl === '/inserare-produs') {
        gasit = true;
    }
    const pattern = /[<>]/;
    // const pattern = /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi;
    const verifica = (obiect) => {
        for(let cheie in obiect) {
            if(typeof obiect[cheie] === 'string' && pattern.test(obiect[cheie])) {
                console.warn("XSS detectat in campul: ", cheie);
                req.session.mesajEroareText = 'Continut nesigur detectat. Codul a fost blocat.';
                if(gasit) {
                    if(req.file.filename){
                        stergePoze(req.file.filename);
                        req.file = null;
                    }
                }
                req.eroareFlag = true;
                return true;
            }
        }
        req.eroareFlag = false;
        return false;
    }
    
    if(req) {
        if(verifica(req.body) || verifica(req.query) || verifica(req.params)) {
            if(res) {
                return res.redirect('/');
            }
        };
    }

    if(next) {
        next();
    }
}

module.exports = xssFilter;