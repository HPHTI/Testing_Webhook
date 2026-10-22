// Puente Meta -> .NET (Render). Reemplaza tu index.js actual. Mismas dependencias: express, axios (https viene con Node).
//
// Variables de entorno en Render:
//   VERIFY_TOKEN        (ya la tienes)  token de verificacion que capturas en Meta
//   APP_SECRET          (NUEVA)         App Secret de la app de Meta. Con ella el puente rechaza peticiones sin firma valida.
//                                       Es el MISMO valor que MetaWebhook:AppSecret en el appsettings.json de .NET.
//   TARGET_URL          (opcional)      por defecto https://ppa.tnghph.com.mx:222/webhook
//   FORWARD_TIMEOUT_MS  (opcional)      por defecto 1800000 (30 min) para que .NET termine de procesar
//   PORT                (ya la tienes)

const express = require('express');
const axios = require('axios');
const https = require('https');
const crypto = require('crypto');

const app = express();

// Guarda el cuerpo CRUDO ademas del JSON: la firma de Meta solo es valida sobre los bytes originales.
app.use(express.json({
  limit: '5mb',
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;
const appSecret = process.env.APP_SECRET;
const targetUrl = process.env.TARGET_URL || 'https://ppa.tnghph.com.mx:222/Testing';
const forwardTimeoutMs = Number(process.env.FORWARD_TIMEOUT_MS) || 30 * 60 * 1000;

// Agente para ignorar validación SSL (solo para ese webhook)
const insecureAgent = new https.Agent({
  rejectUnauthorized: false
});

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------

// Valida X-Hub-Signature-256: "sha256=" + HMAC-SHA256(cuerpo crudo, App Secret), comparado en tiempo constante.
function firmaValida(cabecera, cuerpoCrudo) {
  if (!appSecret || !cabecera || !Buffer.isBuffer(cuerpoCrudo)) return false;
  const esperada = Buffer.from('sha256=' + crypto.createHmac('sha256', appSecret).update(cuerpoCrudo).digest('hex'));
  const recibida = Buffer.from(String(cabecera).trim().toLowerCase());
  return esperada.length === recibida.length && crypto.timingSafeEqual(esperada, recibida);
}

// Ids (wamid) de los mensajes entrantes. Las notificaciones de estado (entregado, leido) no traen "messages".
function idsDeMensajes(body) {
  const ids = [];
  for (const entry of body?.entry ?? []) {
    for (const change of entry?.changes ?? []) {
      const mensajes = change?.value?.messages;
      if (!Array.isArray(mensajes)) continue;
      for (const m of mensajes) if (m?.id) ids.push(m.id);
    }
  }
  return ids;
}

// Memoria de ids ya reenviados (24 h, maximo 50 000). Meta reintenta una entrega cuando no recibe 200 a tiempo y el
// reintento trae el MISMO id: sin esto el mensaje se procesaria, y se respondería, dos veces.
// OJO: vive en memoria; si Render reinicia o duerme el servicio, se pierde.
const TTL_VISTOS_MS = 24 * 60 * 60 * 1000;
const MAX_VISTOS = 50000;
const vistos = new Map(); // id -> expira

function yaVisto(id) {
  const expira = vistos.get(id);
  if (expira === undefined) return false;
  if (expira <= Date.now()) { vistos.delete(id); return false; }
  return true;
}
function marcarVisto(id) {
  vistos.delete(id);
  vistos.set(id, Date.now() + TTL_VISTOS_MS);
  while (vistos.size > MAX_VISTOS) vistos.delete(vistos.keys().next().value);
}
setInterval(() => {
  const ahora = Date.now();
  for (const [id, expira] of vistos) if (expira <= ahora) vistos.delete(id);
}, 10 * 60 * 1000).unref();

// Solo se reintenta cuando es SEGURO: la peticion no llego (conexion rechazada, DNS) o el servidor dijo 502/503.
// Un timeout o un 504 son ambiguos (.NET pudo haberlo procesado) y reintentar duplicaria la respuesta.
const CODIGOS_SIN_LLEGAR = new Set(['ECONNREFUSED', 'ECONNRESET', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH']);
function esReintentable(error) {
  if (error?.response) return [502, 503].includes(error.response.status);
  return CODIGOS_SIN_LLEGAR.has(error?.code);
}
const dormir = (ms) => new Promise((r) => setTimeout(r, ms));

async function reenviar(cuerpoCrudo, firma) {
  const intentos = 3;
  const esperasMs = [2000, 5000];
  for (let i = 1; ; i++) {
    try {
      return await axios.post(targetUrl, cuerpoCrudo, {
        // Se manda el cuerpo CRUDO y la firma ORIGINAL de Meta: .NET valida X-Hub-Signature-256 de punta a punta.
        headers: { 'Content-Type': 'application/json', 'X-Hub-Signature-256': firma || '' },
        transformRequest: [(data) => data],
        maxBodyLength: Infinity,
        timeout: forwardTimeoutMs,
        httpsAgent: insecureAgent // 🚨 Ignora validación SSL
      });
    } catch (error) {
      if (i >= intentos || !esReintentable(error)) throw error;
      console.warn(`⚠️ Intento ${i}/${intentos} fallo (${error.code || error.response?.status}); reintentando...`);
      await dormir(esperasMs[Math.min(i - 1, esperasMs.length - 1)]);
    }
  }
}

function registrarError(error) {
  console.error('\n❌ Error al enviar la petición:');
  if (error.response) {
    console.error(`- Código HTTP: ${error.response.status}`);
    console.error(`- Status Text: ${error.response.statusText}`);
    console.error(`- Cuerpo respuesta: ${JSON.stringify(error.response.data, null, 2)}`);
    console.error(`- Verify_Token: ${JSON.stringify(verifyToken, null, 2)}`);
    console.error(`- Appsecrets: ${JSON.stringify(appSecret, null, 2)}`);
    console.error(`- Headers: ${JSON.stringify(error.response.headers, null, 2)}`);
  } else if (error.request) {
    console.error('- No hubo respuesta del servidor.');
    console.error(`- Código: ${error.code || 'sin código'}`);
  } else {
    console.error(`- Error al preparar la solicitud: ${error.message}`);
  }
  console.error(`- Stack Trace: ${error.stack}`);
}

// ---------------------------------------------------------------------------
// Rutas
// ---------------------------------------------------------------------------

// GET: verificacion del webhook (sin cambios)
app.get('/', (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('WEBHOOK VERIFIED');
    res.status(200).send(challenge);
  } else {
    res.status(403).end();
  }
});

// POST: mensajes de Meta
app.post('/', (req, res) => {
  const body = req.body;

  // 1) Firma: solo Meta conoce el App Secret. Sin APP_SECRET configurada se avisa y se deja pasar (como antes).
  if (appSecret) {
    if (!firmaValida(req.get('X-Hub-Signature-256'), req.rawBody)) {
      console.warn('🚫 Peticion rechazada: firma X-Hub-Signature-256 ausente o invalida');
      return res.sendStatus(401);
    }
  } else {
    console.warn('⚠️ APP_SECRET no esta configurada: no se valida la firma de Meta');
  }

  // 2) Solo mensajes reales (los estados "entregado/leido" se ignoran, igual que antes)
  const ids = idsDeMensajes(body);
  if (ids.length === 0) {
    console.log('📭 Webhook ignorado (no es mensaje entrante real)');
    return res.sendStatus(200);
  }

  // 3) Duplicados: Meta reintenta la entrega y trae el mismo id
  const nuevos = ids.filter((id) => !yaVisto(id));
  if (nuevos.length === 0) {
    console.log(`♻️ Duplicado ignorado (${ids.join(', ')})`);
    return res.sendStatus(200);
  }
  nuevos.forEach(marcarVisto);

  // 4) Responder 200 a Meta YA. Antes se esperaba la respuesta de .NET (hasta 680 s) y Meta, que reintenta pasados
  //    unos segundos, mandaba el mismo mensaje otra vez. El reenvio sigue en segundo plano.
  res.sendStatus(200);

  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`\n\n📩 Mensaje entrante recibido ${timestamp} (${nuevos.join(', ')})\n`);
  console.log(JSON.stringify(body, null, 2));

  reenviar(req.rawBody, req.get('X-Hub-Signature-256'))
    .then((response) => {
      console.log('\n✅ Petición enviada con éxito:');
      console.log(`- Código HTTP: ${response.status}`);
      console.log(`- Status Text: ${response.statusText}`);
      console.log(`- Respuesta: ${JSON.stringify(response.data, null, 2)}`);
    })
    .catch((error) => {
      registrarError(error);
      // No llego a procesarse: se olvida el id para que una nueva entrega del mismo mensaje no se descarte.
      // (Con timeout o 504 NO se olvida: .NET pudo haberlo procesado y reenviarlo duplicaria la respuesta.)
      if (esReintentable(error)) nuevos.forEach((id) => vistos.delete(id));
    });
});

// Start the server
app.listen(port, () => {
  console.log(`\nListening on port ${port}\n`);
});
