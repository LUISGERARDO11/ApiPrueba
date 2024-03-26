// app.js

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const authMiddleware = require('./middleware/authMiddleware');
const User = require('./models/User'); // Asegúrate de que la ruta del modelo sea correcta

const app = express();
const port = process.env.PORT || 3000;

// Conexión a MongoDB
mongoose.connect(process.env.MONGO_URI, { dbName: 'smarthomesweepers', useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Conectado a MongoDB');
    app.listen(port, () => {
      console.log('Corriendo en el puerto ' + port);
    });
  })
  .catch(error => {
    console.error('Error al conectar a MongoDB:', error);
    process.exit(1); // Detener la ejecución de la aplicación en caso de error
  });

// Middleware para el manejo de JSON
app.use(express.json());

// Ruta de registro
app.post('/register', async (req, res) => {
  try {
    const {
      nombre_completo,
      correo,
      tipo,
      contrasenia,
      pregunta_secreta,
      respuesta_secreta,
      direccion,
      telefono
    } = req.body;
    // Hash del password
    const hashedPassword = await bcrypt.hash(contrasenia, 10);
    const user = new User({
      nombre_completo,
      correo,
      tipo,
      contrasenia: hashedPassword,
      pregunta_secreta,
      respuesta_secreta,
      direccion,
      telefono,
      fecha_registro: Date.now()
    });
    await user.save();
    res.status(201).send('Usuario registrado exitosamente');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al registrar el usuario');
  }
});

// Ruta de inicio de sesión
app.post('/login', async (req, res) => {
  try {
    const { correo, contrasenia } = req.body;
    // Buscar el usuario en la base de datos
    const user = await User.findOne({ correo });
    if (!user) {
      return res.status(404).send('Usuario no encontrado');
    }
    // Comparar la contraseña
    const validPassword = await bcrypt.compare(contrasenia, user.contrasenia);
    if (!validPassword) {
      return res.status(401).send('Contraseña incorrecta');
    }
    // Crear y enviar el token JWT
    const token = jwt.sign({ userId: user._id }, 'tu_secreto');
    res.header('auth-token', token).send(token);
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al iniciar sesión');
  }
});

// Ruta protegida
app.get('/protected', authMiddleware, (req, res) => {
  res.send('Ruta protegida');
});
