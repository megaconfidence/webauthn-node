const express = require("express");
const session = require("express-session");

const {
  verifyRegistrationResponse,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  generateAuthenticationOptions,
} = require("@simplewebauthn/server");
const {
  isoBase64URL,
  isoUint8Array,
} = require("@simplewebauthn/server/helpers");

const { nanoid } = require("nanoid");
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
    authenticators: [],
    id: nanoid(5),
    username: uname,
  };

  const { id: userID, username: userName, authenticators } = user;

  const opts = {
    rpID,
    rpName,
    userID,
    userName,
    timeout: 60000,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "discouraged",
      userVerification: "preferred",
    },
    supportedAlgorithmIDs: [-7, -257],
    excludeCredentials: authenticators?.map((dev) => ({
      type: "public-key",
      id: dev.credentialID,
      transports: dev.transports,
    })),
  };
  const options = await generateRegistrationOptions(opts);

  req.session.challenge = { user, challenge: options.challenge };
  res.send(options);
});

app.post("/register/complete", async (req, res) => {
  const response = req.body;
  const { challenge: expectedChallenge, user } = req.session.challenge;

  const opts = {
    response,
    expectedOrigin,
    expectedRPID: rpID,
    requireUserVerification: false,
    expectedChallenge: `${expectedChallenge}`,
  };
  let verification = await verifyRegistrationResponse(opts).catch((error) => {
    console.error(error);
    return res.status(400).send({ error: error.message });
  });

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    const { credentialPublicKey, credentialID, counter } = registrationInfo;

    const authenticator = user.authenticators.find((authenticator) =>
      isoUint8Array.areEqual(authenticator.credentialID, credentialID)
    );

    if (!authenticator) {
      user.authenticators.push({
        counter,
        credentialID: Array.from(credentialID),
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
    timeout: 60000,
    userVerification: "preferred",
    allowCredentials: user.authenticators.map((dev) => ({
      type: "public-key",
      id: dev.credentialID,
      transports: dev.transports,
    })),
  };
  const options = await generateAuthenticationOptions(opts);

  req.session.challenge = { user, challenge: options.challenge };
  res.send(options);
});

app.post("/login/complete", async (req, res) => {
  const { challenge: expectedChallenge, user } = req.session.challenge;
  const body = req.body;

  const bodyCredIDBuffer = isoBase64URL.toBuffer(body.rawId);
  const authenticator = user.authenticators.find((authenticator) =>
    isoUint8Array.areEqual(authenticator.credentialID, bodyCredIDBuffer)
  );
  if (!authenticator) {
    return res.status(400).send({ error: "Authenticator is not registered" });
  }

  const opts = {
    authenticator,
    response: body,
    expectedOrigin,
    expectedRPID: rpID,
    requireUserVerification: false,
    expectedChallenge: `${expectedChallenge}`,
  };
  const verification = await verifyAuthenticationResponse(opts).catch(
    (error) => {
      console.error(error);
      return res.status(400).send({ error: error.message });
    }
  );

  const { verified, authenticationInfo } = verification;

  if (verified) {
    authenticator.counter = authenticationInfo.newCounter;
    user.authenticators = user.authenticators.map((i) =>
      i.id == authenticator.id ? authenticator : i
    );
    localStorage.setItem(user.username, JSON.stringify(user));
  }

  req.session.challenge = undefined;
  res.send({ verified });
});

app.listen(port, () => {
  console.log(`🚀 Server ready on port ${port}`);
});
