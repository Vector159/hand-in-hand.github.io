// Importar dependencias
const express = require('express');
const cors = require('cors');
const path = require('path');
const mysql = require('mysql2/promise');
const session = require('express-session');
const nodemailer = require('nodemailer');
const axios = require('axios'); // Para verificar el CAPTCHA con Google

// Inicializar aplicación Express
const app = express();
const PORT = process.env.PORT || 3000;

// Determinar el entorno (desarrollo o producción)
const isProduction = process.env.NODE_ENV === 'production';

// ===== CONFIGURACIÓN DE LA BASE DE DATOS =====
// Configuración para desarrollo local y producción (Hostinger)
const dbConfig = {
  // Configuración para desarrollo local
  development: {
    host: 'localhost',
    user: 'root',           // Usuario local de MySQL
    password: '',           // Contraseña local (vacía por defecto)
    database: 'handinhand', // Base de datos local
  },
  // Configuración para producción (Hostinger)
  production: {
    host: 'localhost',                // En Hostinger, es 'localhost'
    user: 'u843214921_Cooding',       // Tu usuario en Hostinger
    password: 'Cooding060302',   // IMPORTANTE: Reemplaza con tu contraseña real
    database: 'u843214921_handinhand' // Tu base de datos en Hostinger
  }
};

// Seleccionar configuración según el entorno
const activeConfig = isProduction ? dbConfig.production : dbConfig.development;

// Crear pool de conexiones
const pool = mysql.createPool({
  ...activeConfig,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Verificación de conexión a MySQL
const testDbConnection = async () => {
  try {
    const conn = await pool.getConnection();
    console.log(`✅ Conexión a MySQL establecida (${isProduction ? 'producción' : 'desarrollo'})`);
    console.log(`   Host: ${activeConfig.host}, DB: ${activeConfig.database}, User: ${activeConfig.user}`);
    conn.release();
  } catch (err) {
    console.error('❌ Error al conectar a MySQL:', err.message);
    console.error('Detalles del error:', err);
  }
};

// Probar la conexión al iniciar
testDbConnection();

// ===== CONFIGURACIÓN DE NODEMAILER PARA ENVÍO DE CORREOS =====
// Crear transporter para envío de correos
let transporter;

function initializeMailer() {
  // Configuración para Gmail
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER || 'valeriacabrera965@gmail.com', // Reemplaza con tu correo
      pass: process.env.EMAIL_PASS || 'dnkv jlhk etxs nvcz'  // Reemplaza con tu contraseña de aplicación
    }
  });
  
  // Verificar conexión al servicio de correo
  transporter.verify((error, success) => {
    if (error) {
      console.error('❌ Error al configurar el servicio de correo:', error);
    } else {
      console.log('✅ Servidor listo para enviar correos');
    }
  });
}

// Inicializar el servicio de correo
initializeMailer();

// Función para enviar correo de verificación
async function enviarCorreoVerificacion(email, nombre, codigo) {
  try {
    const mailOptions = {
      from: '"Hand in Hand" <valeria@gmail.com>', // Reemplaza con tu correo
      to: email,
      subject: 'Verificación de cuenta - Hand in Hand',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
          <h2 style="color: #333;">¡Hola ${nombre}!</h2>
          <p>Gracias por registrarte en Hand in Hand. Para completar tu registro, por favor utiliza el siguiente código de verificación:</p>
          <div style="background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
            ${codigo}
          </div>
          <p>Este código expirará en 15 minutos.</p>
          <p>Si no has solicitado este código, puedes ignorar este correo.</p>
          <p style="margin-top: 30px; font-size: 12px; color: #777;">
            Este es un correo automático, por favor no respondas a este mensaje.
          </p>
        </div>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Correo enviado a ${email}: ${info.messageId}`);
    return true;
  } catch (error) {
    console.error('❌ Error al enviar correo:', error);
    throw error;
  }
}

// ===== MIDDLEWARES =====
// Configuración CORS
app.use(cors({
  origin: function(origin, callback) {
    // Permitir solicitudes sin origen (como las de las herramientas de API)
    if (!origin) return callback(null, true);
    
    // Lista de orígenes permitidos
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:5000',
      'http://localhost:8000',
      'http://localhost:8080',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5000',
      'http://127.0.0.1:8000',
      'http://127.0.0.1:8080',
      'https://ghostwhite-mallard-343152.hostingersite.com'
    ];
    
    if (allowedOrigins.indexOf(origin) !== -1 || !isProduction) {
      callback(null, true);
    } else {
      callback(new Error('No permitido por CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Parseo de JSON y formularios
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Configuración de sesión
app.use(session({
  secret: 'mi_secreto_super_seguro', // Cambia esto por una clave segura
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: isProduction, // true en producción si usas HTTPS
    httpOnly: true,
    maxAge: 3600000 // 1 hora
  }
}));

// Servir archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// ===== RUTAS =====
// Ruta principal
app.get('/', (req, res) => {
  res.send(`Servidor funcionando correctamente - Modo: ${isProduction ? 'Producción' : 'Desarrollo'}`);
});

// Health Check Endpoint
app.get('/health', async (req, res) => {
  try {
    const [dbResult] = await pool.query('SELECT 1');
    res.status(200).json({
      status: 'OK',
      mode: isProduction ? 'production' : 'development',
      db: dbResult ? 'connected' : 'disconnected',
      dbConfig: {
        host: activeConfig.host,
        database: activeConfig.database,
        user: activeConfig.user
      },
      uptime: process.uptime()
    });
  } catch (error) {
    res.status(503).json({ 
      status: 'SERVICE_UNAVAILABLE', 
      error: error.message,
      mode: isProduction ? 'production' : 'development'
    });
  }
});

// ===== FUNCIÓN PARA VERIFICAR CAPTCHA =====
async function verificarCaptcha(token) {
  try {
    // Si el token es 'simulado', aceptarlo directamente (para nuestro simulador de CAPTCHA)
    if (token === 'simulado') {
      console.log('✅ Usando CAPTCHA simulado');
      return true;
    }
    
    // Si estamos en desarrollo, aceptar cualquier token para facilitar las pruebas
    if (!isProduction) {
      console.log('✅ Modo desarrollo: CAPTCHA aceptado automáticamente');
      return true;
    }
    
    // Clave secreta de reCAPTCHA - Con tu clave secreta
    const secretKey = '6LdPjDcrAAAAAC478x2mRUiysm9Sdn8Qj3_mEV3I';
    
    // Verificar con la API de Google
    const response = await axios.post(
      'https://www.google.com/recaptcha/api/siteverify',
      null,
      {
        params: {
          secret: secretKey,
          response: token
        }
      }
    );
    
    // Verificar resultado
    if (response.data.success) {
      console.log('✅ CAPTCHA verificado correctamente');
      return true;
    } else {
      console.warn('⚠️ Verificación de CAPTCHA fallida:', response.data['error-codes']);
      return false;
    }
  } catch (error) {
    console.error('❌ Error al verificar CAPTCHA:', error);
    return false;
  }
}

// ===== ENDPOINTS DE AUTENTICACIÓN =====
// Endpoint para enviar código de verificación
app.post('/enviar-codigo', async (req, res, next) => {
  try {
    const { email, nombre, password, captchaToken } = req.body;
    
    // Validación básica
    if (!email || !nombre || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Todos los campos son requeridos'
      });
    }

    // Validación de CAPTCHA (solo en producción)
    if (isProduction) {
      if (!captchaToken) {
        return res.status(400).json({
          success: false,
          error: 'Verificación CAPTCHA requerida'
        });
      }

      const captchaValido = await verificarCaptcha(captchaToken);
      if (!captchaValido) {
        return res.status(400).json({
          success: false,
          error: 'Verificación CAPTCHA fallida. Por favor, inténtalo de nuevo.'
        });
      }
    } else {
      console.log('⚠️ Modo desarrollo: Verificación CAPTCHA omitida');
    }

    // Validación de formato de email
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'Formato de correo electrónico inválido'
      });
    }

    // Verificar si el correo ya está registrado
    try {
      const [existing] = await pool.execute(
        'SELECT id FROM usuarios WHERE correo_usuario = ?', 
        [email]
      );

      if (existing.length > 0) {
        return res.status(409).json({
          success: false,
          error: 'Este correo ya está registrado'
        });
      }
    } catch (dbError) {
      console.error('Error al verificar usuario existente:', dbError);
      // Si la tabla no existe, continuamos con el proceso
      if (dbError.code !== 'ER_NO_SUCH_TABLE') {
        throw dbError;
      }
    }

    // Generar código de verificación simple
    const codigo = Math.floor(100000 + Math.random() * 900000).toString();
    const fechaExpiracion = new Date(Date.now() + 15 * 60 * 1000);
    
    // Enviar correo con el código de verificación
    try {
      await enviarCorreoVerificacion(email, nombre, codigo);
    } catch (emailError) {
      console.error('Error al enviar correo:', emailError);
      return res.status(500).json({
        success: false,
        error: 'Error al enviar el correo de verificación'
      });
    }
    
    // Guardar datos temporales en la sesión
    req.session.tempUser = {
      email,
      nombre,
      password
    };
    req.session.codigoGenerado = codigo;
    req.session.intentos = 0;
    
    res.json({ 
      success: true,
      expiresAt: fechaExpiracion.getTime(),
      message: 'Código enviado correctamente a tu correo'
    });

  } catch (error) {
    console.error('🔥 Error en /enviar-codigo:', error);
    next(error);
  }
});

// Verificación de código
app.post('/verificar-codigo', async (req, res, next) => {
  try {
    const { codigoIngresado } = req.body;
    
    if (!codigoIngresado || typeof codigoIngresado !== 'string' || codigoIngresado.length !== 6) {
      return res.status(400).json({
        success: false,
        error: "El código debe tener exactamente 6 dígitos"
      });
    }

    // Verificar intentos
    req.session.intentos = (req.session.intentos || 0) + 1;
    if (req.session.intentos > 5) {
      return res.status(429).json({
        success: false,
        error: "Demasiados intentos fallidos"
      });
    }

    // Comparación directa
    if (codigoIngresado === req.session.codigoGenerado) {
      if (!req.session.tempUser?.email) {
        return res.status(400).json({
          success: false,
          error: "Sesión expirada o inválida"
        });
      }

      try {
        // Intentar crear la tabla si no existe
        await pool.execute(`
          CREATE TABLE IF NOT EXISTS usuarios (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nombre_usuario VARCHAR(100) NOT NULL,
            correo_usuario VARCHAR(100) NOT NULL UNIQUE,
            contrasena VARCHAR(255) NOT NULL,
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )
        `);

        // Registrar usuario
        const [result] = await pool.execute(
          'INSERT INTO usuarios (nombre_usuario, correo_usuario, contrasena) VALUES (?, ?, ?)',
          [req.session.tempUser.nombre, req.session.tempUser.email, req.session.tempUser.password]
        );

        console.log(`✅ Usuario registrado: ${req.session.tempUser.email} (ID: ${result.insertId})`);
        
        // Limpiar sesión
        req.session.tempUser = null;
        req.session.codigoGenerado = null;
        req.session.intentos = null;
        
        return res.json({ 
          success: true,
          userId: result.insertId,
          message: "Usuario registrado correctamente"
        });
      } catch (dbError) {
        console.error('Error al registrar usuario:', dbError);
        return res.status(500).json({
          success: false,
          error: "Error al registrar usuario en la base de datos"
        });
      }
    }

    console.warn(`⚠️ Intento fallido de verificación para ${req.session.tempUser?.email}`);
    res.status(400).json({ 
      success: false,
      error: "Código incorrecto",
      intentosRestantes: 5 - req.session.intentos
    });

  } catch (error) {
    console.error('🔥 Error en /verificar-codigo:', error);
    next(error);
  }
});

// Endpoint de login
app.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    
    // Validación básica
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email y contraseña son requeridos'
      });
    }

    try {
      // Buscar usuario por email
      const [users] = await pool.execute(
        'SELECT id, nombre_usuario, correo_usuario, contrasena FROM usuarios WHERE correo_usuario = ?',
        [email]
      );

      if (users.length === 0) {
        return res.status(401).json({
          success: false,
          error: 'Credenciales inválidas'
        });
      }

      const user = users[0];
      
      // Comparar contraseña (sin encriptar)
      if (password !== user.contrasena) {
        return res.status(401).json({
          success: false,
          error: 'Credenciales inválidas'
        });
      }

      // Crear sesión de usuario
      req.session.userId = user.id;
      req.session.userEmail = user.correo_usuario;
      req.session.userName = user.nombre_usuario;
      
      // Responder con datos del usuario (sin la contraseña)
      res.json({
        success: true,
        user: {
          id: user.id,
          email: user.correo_usuario,
          nombre: user.nombre_usuario
        },
        message: 'Inicio de sesión exitoso'
      });
    } catch (dbError) {
      console.error('Error al buscar usuario:', dbError);
      if (dbError.code === 'ER_NO_SUCH_TABLE') {
        return res.status(401).json({
          success: false,
          error: 'Credenciales inválidas'
        });
      }
      throw dbError;
    }

  } catch (error) {
    console.error('🔥 Error en /login:', error);
    next(error);
  }
});

// Endpoint para cerrar sesión
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        success: false,
        error: 'Error al cerrar sesión'
      });
    }
    
    res.json({
      success: true,
      message: 'Sesión cerrada correctamente'
    });
  });
});

// Endpoint para verificar sesión actual
app.get('/session', (req, res) => {
  if (req.session.userId) {
    res.json({
      success: true,
      user: {
        id: req.session.userId,
        email: req.session.userEmail,
        nombre: req.session.userName
      }
    });
  } else {
    res.status(401).json({
      success: false,
      error: 'No hay sesión activa'
    });
  }
});

// ===== MANEJADOR DE ERRORES =====
app.use((err, req, res, next) => {
  console.error('🚨 Error:', err.message);
  res.status(500).json({
    success: false,
    error: 'Error interno del servidor'
  });
});

// ===== INICIAR SERVIDOR =====
app.listen(PORT, () => {
  console.log(`🟢 Servidor corriendo en http://localhost:${PORT} (${isProduction ? 'producción' : 'desarrollo'})`);
  console.log(`🔒 Modo CAPTCHA: ${isProduction ? 'Verificación completa' : 'Verificación omitida (desarrollo)'}`);
}).on('error', (err) => {
  console.error('❌ Error al iniciar servidor:', err);
  process.exit(1);
});

module.exports = app;