const express = require('express');
const bodyParser = require('body-parser');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const cors = require("cors");
const { webcrypto } = require("crypto");

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}
const app = express();
app.use(cors());
app.use(bodyParser.json());

// In-memory user store (replace with DB in production)
const usersDB = {}; // { username: { passkeys: [], currentRegOpts, currentAuthOpts } }

// ------------------------
// Helper functions
// ------------------------
function getUser(username) {
  return usersDB[username] || null;
}

function createUser(username) {
  usersDB[username] = { username, passkeys: [] };
  return usersDB[username];
}

function getRPInfo(req) {
  const origin = req.headers.origin || 'http://localhost:3000';
  const rpID = new URL(origin).hostname || 'localhost';
  const rpName = rpID; // or any friendly name
  return { origin, rpID, rpName };
}


// ------------------------
// 1. Generate Registration Options
// ------------------------
app.post('/register/options',async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Missing username' });

  let user = getUser(username) || createUser(username);
  const { origin, rpID, rpName } = getRPInfo(req);

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: user.username,
    attestationType: 'none',
    excludeCredentials: user.passkeys.map(pk => ({
      id: pk.id,
      transports: pk.transports,
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
      authenticatorAttachment: 'platform',
    },
  });
  console.log("options",options)
  user.currentRegOpts = options;
  return res.json(options);
});

// ------------------------
// 2. Verify Registration Response
// ------------------------
app.post('/register/verify', async(req, res) => {
  const { username, attestation } = req.body;
  if (!username || !attestation) {
    return res.status(400).json({ error: 'Missing parameters' });
  }

  const user = getUser(username);
  if (!user) return res.status(404).json({ error: 'User not found' });

    const { origin, rpID } = getRPInfo(req);

  try {
    const verification = await verifyRegistrationResponse({
      response: attestation,
      expectedChallenge: user.currentRegOpts.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    const { verified, registrationInfo } = verification;
    if (verified && registrationInfo) {
      const { id, publicKey, counter, transports } = registrationInfo.credential;
      user.passkeys.push({
        id,
        publicKey,
        counter,
        transports,
      });
    }

    return res.json({ verified });
  } catch (err) {
    console.error(err);
    return res.status(400).json({ error: err.message });
  }
});

// ------------------------
// 3. Generate Authentication Options
// ------------------------
app.post('/login/options', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Missing parameters' });

  const user = getUser(username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { rpID } = getRPInfo(req);
  console.log(rpID)
  console.log(user)
  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: user.passkeys.map(pk => ({
      id: pk.id,
      transports: pk.transports,
    })),
  });

  user.currentAuthOpts = options;
  return res.json(options);
});

// ------------------------
// 4. Verify Authentication Response
// ------------------------
app.post('/login/verify', async(req, res) => {
  const { username, assertion } = req.body;
  if (!username || !assertion) return res.status(400).json({ error: 'Missing parameters' });


  const user = getUser(username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { origin, rpID } = getRPInfo(req);

  const passkey = user.passkeys.find(pk => pk.id === assertion.id);
  if (!passkey) return res.status(400).json({ error: 'Passkey not found' });

  try {
    const verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge: user.currentAuthOpts.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: passkey.id,
        publicKey: passkey.publicKey,
        counter: passkey.counter,
        transports: passkey.transports,
      },
    });

    const { verified, authenticationInfo } = verification;

    if (verified && authenticationInfo) {
      passkey.counter = authenticationInfo.newCounter;
    }

    return res.json({ verified });
  } catch (err) {
    console.error(err);
    return res.status(400).json({ error: err.message });
  }
});

// ------------------------
app.listen(4000, () => console.log('WebAuthn server running on http://localhost:4000'));
