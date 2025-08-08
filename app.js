// Import Express.js
const express = require('express');
const axios = require('axios');
const https = require('https');

// Create an Express app
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Set port and verify_token
const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;

// Agente para ignorar validación SSL (solo para ese webhook)
const insecureAgent = new https.Agent({
  rejectUnauthorized: false
});

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

  // Verificamos si el webhook contiene mensajes reales
  const tieneMensajes = body?.entry?.some(entry =>
    entry?.changes?.some(change =>
      change?.value?.messages && Array.isArray(change.value.messages)
    )
  );

  if (!tieneMensajes) {
    console.log("📭 Webhook ignorado (no es mensaje entrante real)");
    return res.sendStatus(200);
  }

  // Si llega aquí, es mensaje real
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`\n\n📩 Mensaje entrante recibido ${timestamp}\n`);
  console.log(JSON.stringify(body, null, 2));

  try {
    const response = await axios.post('https://ppa.tnghph.com.mx:222/webhook', body, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 180000,
      httpsAgent: insecureAgent // 🚨 Ignora validación SSL
    });

    console.log('\n✅ Petición enviada con éxito:');
    console.log(`- Código HTTP: ${response.status}`);
    console.log(`- Status Text: ${response.statusText}`);
    console.log(`- Respuesta: ${JSON.stringify(response.data, null, 2)}`);

  } catch (error) {
    console.error('\n❌ Error al enviar la petición:');

    if (error.response) {
      console.error(`- Código HTTP: ${error.response.status}`);
      console.error(`- Status Text: ${error.response.statusText}`);
      console.error(`- Headers: ${JSON.stringify(error.response.headers, null, 2)}`);
      console.error(`- Cuerpo respuesta: ${JSON.stringify(error.response.data, null, 2)}`);
    } else if (error.request) {
      console.error('- No hubo respuesta del servidor.');
      console.error(`- Request: ${error.request._currentRequest ? error.request._currentRequest._header : 'Sin headers capturados'}`);
    } else {
      console.error(`- Error al preparar la solicitud: ${error.message}`);
    }

    console.error(`- Stack Trace: ${error.stack}`);
  }

  res.sendStatus(200);
});

// Start the server
app.listen(port, () => {
  console.log(`\nListening on port ${port}\n`);
});
