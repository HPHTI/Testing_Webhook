// Import Express.js
const express = require('express');
const axios = require('axios');
// Create an Express app
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Set port and verify_token
const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;

// Route for GET requests
app.get('/', (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('WEBHOOK VERIFIED');
    res.status(200).send(challenge);
  } else {
    res.status(403).end();
  }
});

// Route for POST requests
app.post('/', async (req, res) => {
  const body = req.body;

  // Verificar si es un mensaje entrante
  if (
    body?.entry?.[0]?.changes?.[0]?.value?.messages &&
    Array.isArray(body.entry[0].changes[0].value.messages)
  ) {
    const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
    console.log(`\n\n📩 Mensaje entrante recibido ${timestamp}\n`);
    console.log(JSON.stringify(body, null, 2));
  }

    // Enviar el body al webhook externo
  try {
    const response = await axios.post('http://ppa.tnghph.com.mx:222/webhook', body, {
      headers: {
        'Content-Type': 'application/json'
      },
      timeout: 5000 // para evitar que se quede colgado
    });

    console.log('\n✅ Petición enviada con éxito:');
    console.log(`- Código HTTP: ${response.status}`);
    console.log(`- Status Text: ${response.statusText}`);
    console.log(`- Respuesta: ${JSON.stringify(response.data, null, 2)}`);

  } catch (error) {
    console.error('\n❌ Error al enviar la petición:');

    if (error.response) {
      // El servidor respondió con un código distinto a 2xx
      console.error(`- Código HTTP: ${error.response.status}`);
      console.error(`- Status Text: ${error.response.statusText}`);
      console.error(`- Headers: ${JSON.stringify(error.response.headers, null, 2)}`);
      console.error(`- Cuerpo respuesta: ${JSON.stringify(error.response.data, null, 2)}`);
    } else if (error.request) {
      // La solicitud fue enviada pero no hubo respuesta
      console.error('- No hubo respuesta del servidor.');
      console.error(`- Request: ${error.request._currentRequest ? error.request._currentRequest._header : 'Sin headers capturados'}`);
    } else {
      // Error al configurar la solicitud
      console.error(`- Error al preparar la solicitud: ${error.message}`);
    }

    console.error(`- Stack Trace: ${error.stack}`);
  }


  // Siempre responder 200 OK para evitar reintentos
  res.sendStatus(200);
});

// Start the server
app.listen(port, () => {
  console.log(`\nListening on port ${port}\n`);
});