require('dotenv').config();

const bcrypt = require('bcrypt');
const saltRounds = 10; 

const express = require('express');
const session = require('express-session');
const path = require('path');
const cors = require('cors');
const mysql = require('mysql2');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configuración de base de datos
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) console.error('❌ Error conectando a MySQL:', err.message);
    else console.log('✅ Base de datos conectada.');
});

// Configuración de sesiones
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true 
    }
}));

app.use(express.static(path.join(__dirname, 'public')));

// --- NUEVA FUNCIÓN DE ENVÍO CON BREVO (API HTTP) ---
const enviarCorreo = async (email, asunto, htmlContent) => {
    try {
        const response = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: {
                'accept': 'application/json',
                'api-key': process.env.BREVO_API_KEY,
                'content-type': 'application/json',
            },
            body: JSON.stringify({
                sender: {
                    name: 'Equipo Afines',
                    // 👇 AQUÍ DEBES PONER EL CORREO CON EL QUE TE REGISTRES EN BREVO
                    email: 'castillomayabrandon@gmail.com' 
                },
                to: [
                    { email: email } // Aquí va el correo del usuario que se está registrando
                ],
                subject: asunto,
                htmlContent: htmlContent,
            }),
        });

        if (response.ok) {
            console.log(`✅ Correo enviado con éxito a ${email} a través de Brevo`);
            return true;
        } else {
            const data = await response.json();
            console.error('❌ Error de Brevo:', data);
            throw new Error('Fallo en la API de Brevo');
        }
    } catch (error) {
        console.error('❌ Error en la petición fetch:', error);
        throw error;
    }
};

// --- RUTAS DE REGISTRO ---

app.post('/api/solicitar-registro', async (req, res) => {
    const { nombre, email, password } = req.body;
    const codigo = Math.floor(100000 + Math.random() * 900000);

    req.session.registro_temporal = { nombre, email, password, codigo };
    console.log(`📩 Código de registro generado para ${email}: ${codigo}`);

    const htmlCorreo = `
        <div style="font-family: sans-serif; max-width: 500px; padding: 20px; border: 1px solid #eee; border-radius: 12px;">
            <h2 style="color: #104385;">¡Hola, ${nombre}!</h2>
            <p>Usa el siguiente código para verificar tu cuenta:</p>
            <div style="background-color: #f8fafc; text-align: center; padding: 15px; font-size: 24px; font-weight: bold; letter-spacing: 4px; color: #0CDBEB; border-radius: 8px;">
                ${codigo}
            </div>
        </div>
    `;

    try {
        // Aquí llamamos a la nueva función en lugar de Nodemailer
        await enviarCorreo(email, 'Código de verificación de registro', htmlCorreo);
        res.json({ status: 'success' });
    } catch (error) {
        res.status(500).json({ status: 'error', message: 'Fallo al enviar el código.' });
    }
});

app.post('/api/verificar-registro', async (req, res) => {
    const { codigoIngresado } = req.body;
    const datosTemporales = req.session.registro_temporal;

    if (!datosTemporales) {
        return res.status(400).json({ status: 'error', message: 'La sesión expiró.' });
    }

    if (parseInt(codigoIngresado) === datosTemporales.codigo) {
        try {
            const hashedPassword = await bcrypt.hash(datosTemporales.password, saltRounds);
            const query = 'INSERT INTO usuarios (nombre, email, pass) VALUES (?, ?, ?)';
            const valores = [datosTemporales.nombre, datosTemporales.email, hashedPassword];

            db.query(query, valores, (err, result) => {
                if (err) {
                    console.error("❌ Error MySQL:", err);
                    return res.status(500).json({ status: 'error', message: 'Error de base de datos o correo ya registrado.' });
                }

                req.session.usuario_id = result.insertId;
                req.session.registro_temporal = null; 
                
                console.log(`✅ Nuevo usuario registrado: ${datosTemporales.email}`);
                res.json({ status: 'success', redirect: '/homeScreen.html' });
            });
        } catch (hashError) {
            res.status(500).json({ status: 'error', message: 'Error interno del servidor.' });
        }
    } else {
        res.status(400).json({ status: 'error', message: 'Código incorrecto.' });
    }
});

// --- LOGIN ---
app.post('/api/login', (req, res) => {
    const { email, pass } = req.body; 
    const query = 'SELECT id, nombre, pass FROM usuarios WHERE email = ?';

    db.query(query, [email], async (err, results) => {
        if (err || results.length === 0) return res.status(401).json({ status: 'error', message: 'Credenciales incorrectas' });

        const user = results[0];
        try {
            const match = await bcrypt.compare(pass, user.pass);
            if (match) {
                req.session.usuario_id = user.id;
                res.json({ status: 'success', redirect: '/homeScreen.html' });
            } else {
                res.status(401).json({ status: 'error', message: 'Credenciales incorrectas' });
            }
        } catch (error) {
            res.status(500).json({ status: 'error', message: 'Error en la autenticación.' });
        }
    });
});

// --- LOGOUT ---
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) console.error("Error destruyendo sesión:", err);
        res.redirect('/index.html');
    });
});

// --- RECUPERACIÓN DE CONTRASEÑA ---
app.post('/api/solicitar-recuperacion', (req, res) => {
    const { email } = req.body;
    const query = 'SELECT nombre FROM usuarios WHERE email = ?';
    
    db.query(query, [email], async (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', message: 'Error de servidor' });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Este correo no está registrado.' });
        }

        const nombre = results[0].nombre;
        const codigo = Math.floor(100000 + Math.random() * 900000);

        req.session.recuperacion = { email, codigo, verificado: false };
        console.log(`📩 Código de recuperación generado para ${email}: ${codigo}`);

        const htmlCorreo = `
            <div style="font-family: sans-serif; max-width: 500px; padding: 20px; border: 1px solid #eee; border-radius: 12px;">
                <h2 style="color: #104385;">Hola, ${nombre}</h2>
                <p>Usa este código para restablecer tu contraseña:</p>
                <div style="background-color: #f8fafc; text-align: center; padding: 15px; font-size: 24px; font-weight: bold; letter-spacing: 4px; color: #0CDBEB; border-radius: 8px;">
                    ${codigo}
                </div>
            </div>
        `;

        try {
            // Aquí también usamos la nueva función
            await enviarCorreo(email, 'Recuperación de contraseña', htmlCorreo);
            res.json({ status: 'success' });
        } catch (error) {
            res.status(500).json({ status: 'error', message: 'Fallo al enviar el código.' });
        }
    });
});

app.post('/api/verificar-recuperacion', (req, res) => {
    const { codigoIngresado } = req.body;
    const datos = req.session.recuperacion;

    if (!datos) {
        return res.status(400).json({ status: 'error', message: 'La sesión expiró. Vuelve a intentarlo.' });
    }

    if (parseInt(codigoIngresado) === datos.codigo) {
        req.session.recuperacion.verificado = true;
        res.json({ status: 'success' });
    } else {
        res.status(400).json({ status: 'error', message: 'El código es incorrecto.' });
    }
});

app.post('/api/cambiar-password', async (req, res) => {
    const { nuevaPassword } = req.body;
    const datos = req.session.recuperacion;

    if (!datos || !datos.verificado) {
        return res.status(403).json({ status: 'error', message: 'No estás autorizado para hacer esto.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(nuevaPassword, saltRounds);
        const query = 'UPDATE usuarios SET pass = ? WHERE email = ?';
        
        db.query(query, [hashedPassword, datos.email], (err) => {
            if (err) {
                console.error("Error al actualizar contraseña:", err);
                return res.status(500).json({ status: 'error', message: 'Error de base de datos.' });
            }

            console.log(`✅ Contraseña actualizada para: ${datos.email}`);
            req.session.recuperacion = null; 
            res.json({ status: 'success' });
        });
    } catch (error) {
        res.status(500).json({ status: 'error', message: 'Error al procesar la contraseña.' });
    }
});

app.get('/api/usuario-actual', (req, res) => {
    if (req.session.usuario_id) {
        db.query('SELECT nombre FROM usuarios WHERE id = ?', [req.session.usuario_id], (err, results) => {
            if (results && results.length > 0) {
                res.json({ nombre: results[0].nombre });
            } else {
                res.status(401).json({ error: 'No autorizado' });
            }
        });
    } else {
        res.status(401).json({ error: 'No logueado' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en el puerto ${PORT}`);
});