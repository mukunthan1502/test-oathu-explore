import { stringify } from "ajv";
import React, { useEffect, useState, useRef } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  useNavigate,
  useLocation,
  json,
} from "react-router-dom";

function base64UrlEncode(str) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await window.crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(digest);
}

function generateCodeVerifier() {
  const array = new Uint32Array(43);
  window.crypto.getRandomValues(array);
  return Array.from(array, (dec) => ("0" + dec.toString(16)).substr(-2)).join(
    ""
  );
}

// Generate code verifier and code challenge
const codeVerifier = generateCodeVerifier();
generateCodeChallenge(codeVerifier).then((codeChallenge) => {
  console.log("Code Verifier:", codeVerifier);
  console.log("Code Challenge:", codeChallenge);
});

const Home = () => {
  // const [codeVerifier, setCodeVerifier] = useState('');
  const [loggedIn, setLoggedIn] = useState(
    () => !!sessionStorage.getItem("access_token")
  );
  const [apiResponse, setApiResponse] = useState("");

  useEffect(() => {
    setLoggedIn(!!sessionStorage.getItem("access_token"));
  }, []);

  const onClick = async () => {
    if (loggedIn) {
      sessionStorage.removeItem("access_token");
      setLoggedIn(false);
      return;
    }
    // debugger
    const verifier = generateCodeVerifier();
    // setCodeVerifier(verifier);
    sessionStorage.setItem("code_verifier", verifier);
    const challenge = await generateCodeChallenge(verifier);

    const authUrl = `https://dev-ptqk6ibc8njgm5ty.us.auth0.com/authorize?response_type=code&client_id=xmPoVoVk6WrffxGwPhDyOVUB3uhuDqre&state=12345&redirect_uri=http://localhost:3000/redirect&code_challenge=${challenge}&code_challenge_method=S256&prompt=login`;
    window.location.href = authUrl;
  };

  const apiProtected = async () => {
    const response = await fetch("http://localhost:8000/protected", {
      headers: {
        Authorization: `Bearer ${sessionStorage.getItem("access_token")}`,
      },
    });
    const json = await response.json();
    setApiResponse(json);
    console.log("response-get::", json);
  };

  return (
    <>
      <div>
        <h1>Site.</h1>
        <button onClick={onClick}>{loggedIn ? "Sign Out" : "Sign In"}</button>
        <button onClick={apiProtected}>Protect GET URL call</button>
        <button onClick={() => setApiResponse("")}>Clear</button>
      </div>
      <div>{JSON.stringify(apiResponse)}</div>
    </>
  );
};

const Redirect = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const isRequestSent = useRef(false); // Use ref instead of state

  useEffect(() => {
    const query = new URLSearchParams(location.search);
    const code = query.get("code");
    const state = query.get("state");
    const codeVerifier = sessionStorage.getItem("code_verifier");

    if (code && codeVerifier && !isRequestSent.current) {
      isRequestSent.current = true; // Set the ref value
      // Exchange the authorization code for an access token
      // debugger
      fetch("https://dev-ptqk6ibc8njgm5ty.us.auth0.com/oauth/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          grant_type: "authorization_code",
          redirect_uri: "http://localhost:3000/redirect",
          client_id: "xmPoVoVk6WrffxGwPhDyOVUB3uhuDqre",
          client_secret:
            "0F0Kn0j_SrecdoUrzHVFgXKWA-qE4BBOxdvDbTrGGllGmVSNgmKyLGVjI7WfaWzT",
          code_verifier: codeVerifier,
          code: code,
        }),
      })
        .then((response) => response.json())
        .then((data) => {
          console.log(data);
          if (!data.error) {
            sessionStorage.setItem("access_token", data.access_token);
            sessionStorage.removeItem("code_verifier");
            // location.href = 'http://localhost:3000/';
            navigate("/");
          }
          // Handle the access token
        })
        .catch((error) => {
          console.error("Error:", error);
        });
    }
  }, [location.search]);

  return (
    <div>
      <h1>Handling Redirect...</h1>
    </div>
  );
};

const App = () => {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/redirect" element={<Redirect />} />
      </Routes>
    </Router>
  );
};

export default App;
