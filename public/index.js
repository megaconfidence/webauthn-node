const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

const msgTxt = document.querySelector(".message");
const loginBtn = document.querySelector(".login");
const regBtn = document.querySelector(".register");
const unameInput = document.querySelector(".username");

function displayMessage(msg) {
  msgTxt.innerHTML = msg;
}

async function myfetch(url, payload) {
  return await fetch(url, {
    method: "POST",
    body: JSON.stringify(payload),
    headers: { "Content-Type": "application/json" },
  }).then((res) => res.json());
}

regBtn.addEventListener("click", async () => {
  displayMessage("");

  const challenge = await myfetch("/register", { username: unameInput.value });

  let signedChallenge = await startRegistration(challenge).catch((error) => {
    displayMessage(error);
    throw error;
  });

  const verification = await myfetch("/register/complete", signedChallenge);

  if (verification?.verified) {
    displayMessage("Success!");
  } else {
    displayMessage(`<pre>${JSON.stringify(verification)}</pre>`);
  }
});

loginBtn.addEventListener("click", async () => {
  displayMessage("");
  const challenge = await myfetch("/login", { username: unameInput.value });

  let signedChallenge = await startAuthentication(challenge).catch((error) => {
    displayMessage(error);
    throw error;
  });

  const verification = await myfetch("/login/complete", signedChallenge);

  if (verification?.verified) {
    displayMessage("Success!");
  } else {
    displayMessage(`<pre>${JSON.stringify(verification)}</pre>`);
  }
});
