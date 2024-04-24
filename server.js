const express = require("express");
const session = require("express-session");

const {
  verifyRegistrationResponse,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  generateAuthenticationOptions,
} = require("@simplewebauthn/server");

const memoryStore = require("memorystore");
const { LocalStorage } = require("node-localstorage");

const app = express();
const MemoryStore = memoryStore(session);
const localStorage = new LocalStorage("./db");

app.use(express.json());
app.use(express.static("./public/"));
app.use(
  session({
    resave: false,
    secret: "secret123",
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      maxAge: 86400000,
    },
    store: new MemoryStore({
      checkPeriod: 86_400_000,
    }),
  })
);

const port = 3000;
const rpID = "localhost";
const origin = `http://${rpID}`;
const rpName = "WebAuthn Tutorial";
const expectedOrigin = `${origin}:${port}`;

app.post("/register", async (req, res) => {
  const uname = req.body.username;
  const user = JSON.parse(localStorage.getItem(uname)) || {
    passKeys: [],
    username: uname,
  };

  const { username: userName, passKeys } = user;

  const opts = {
    rpID,
    rpName,
    userName,
    attestationType: "none",
    supportedAlgorithmIDs: [-7, -257],
    authenticatorSelection: {
      residentKey: "discouraged",
    },
    excludeCredentials: passKeys?.map((key) => ({
      id: key.id,
      transports: key.transports,
    })),
  };
  const options = await generateRegistrationOptions(opts);

  req.session.challenge = { user, options };
  res.send(options);
});

app.post("/register/complete", async (req, res) => {
  const response = req.body;
  const { options, user } = req.session.challenge;

  const opts = {
    response,
    expectedOrigin,
    expectedRPID: rpID,
    expectedChallenge: options.challenge,
  };

  let verification;
  try {
    verification = await verifyRegistrationResponse(opts);
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    const {
      counter,
      credentialID,
      credentialBackedUp,
      credentialPublicKey,
      credentialDeviceType,
    } = registrationInfo;

    const passKey = user.passKeys.find((key) => key.id === credentialID);

    if (!passKey) {
      user.passKeys.push({
        counter,
        id: credentialID,
        backedUp: credentialBackedUp,
        webAuthnUserID: options.user.id,
        deviceType: credentialDeviceType,
        transports: response.response.transports,
        credentialPublicKey: Array.from(credentialPublicKey),
      });
    }
    localStorage.setItem(user.username, JSON.stringify(user));
  }

  req.session.challenge = undefined;
  res.send({ verified });
});

app.post("/login", async (req, res) => {
  const user = JSON.parse(localStorage.getItem(req.body.username));

  const opts = {
    rpID,
    allowCredentials: user?.passKeys.map((key) => ({
      id: key.id,
      transports: key.transports,
    })),
  };
  const options = await generateAuthenticationOptions(opts);

  req.session.challenge = { user, options };
  res.send(options);
});

app.post("/login/complete", async (req, res) => {
  const { options, user } = req.session.challenge;
  const body = req.body;

  const passKey = user.passKeys.find((key) => key.id === body.id);
  if (!passKey) {
    return res
      .status(400)
      .send({ error: `Could not find passkey ${body.id} for user ${user.id}` });
  }

  const opts = {
    authenticator: passKey,
    response: body,
    expectedOrigin,
    expectedRPID: rpID,
    expectedChallenge: options.challenge,
  };

  let verification;
  try {
    verification = await verifyAuthenticationResponse(opts);
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    passKey.counter = authenticationInfo.newCounter;
    user.passKeys = user.passKeys.map((i) =>
      i.id == passKey.id ? passKey : i
    );
    localStorage.setItem(user.username, JSON.stringify(user));
  }

  req.session.challenge = undefined;
  res.send({ verified });
});

app.listen(port, () => {
  console.log(`🚀 Server ready on port ${port}`);
});
