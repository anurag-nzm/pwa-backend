const express = require("express");
const cors = require("cors");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const base64url = require("base64url");

const app = express();
app.use(cors());
app.use(express.json());

const users = {}; 


const getUser = (username) => {
  if (!users[username])
    users[username] = {
      id: `${Date.now()}`,
      credentials: [],
      currentChallenge: null,
    };
  return users[username];
};


app.post("/register/options", async (req, res) => {
  const { username } = req.body;
  const user = getUser(username);
  const options = await generateRegistrationOptions({
    rpName: "PWA POC",
    userID: base64url.encode(user.id),
    userName: username,
    attestationType: "none",
    authenticatorSelection: { userVerification: "preferred" },
  });

  user.currentChallenge = options.challenge;
  res.json(options);
});


app.post("/register/verify", async (req, res) => {
  const { username, attestation } = req.body;
  const user = getUser(username);

  try {
    const verification = await verifyRegistrationResponse({
      credential: attestation,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: req.headers.origin,
      expectedRPID: req.hostname,
    });

    if (verification.verified) {
      const { credentialPublicKey, credentialID } =
        verification.registrationInfo;
      user.credentials.push({
        credentialID: base64url.encode(newCredential.credentialID), 
        credentialPublicKey: newCredential.credentialPublicKey,
      });
    }

    res.json({ verified: verification.verified });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: err.message });
  }
});


app.post("/login/options", (req, res) => {
  const { username } = req.body;
  const user = getUser(username);

  const options = generateAuthenticationOptions({
    allowCredentials: user.credentials.map((c) => ({
      id: c.credentialID,
      type: "public-key",
      transports: ["internal"],
    })),
    userVerification: "preferred",
  });

  user.currentChallenge = options.challenge;
  res.json(options);
});


app.post("/login/verify", async (req, res) => {
  const { username, assertion } = req.body;
  const user = getUser(username);

  try {
    const verification = await verifyAuthenticationResponse({
      credential: assertion,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: req.headers.origin,
      expectedRPID: req.hostname,
      authenticator: user.credentials[0], 
    });

    res.json({ verified: verification.verified });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: err.message });
  }
});

app.listen(4000, () => console.log("Backend running on http: