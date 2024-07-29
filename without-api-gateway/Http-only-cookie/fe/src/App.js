import React, { useEffect, useState, useRef } from "react";
import {
  BrowserRouter as Router,
  Routes, Route,
  useNavigate,
  useLocation
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
  return Array.from(array, (dec) => ("0" + dec.toString(16)).substr(-2)).join("");
}

const Home = () => {
  const [loggedIn, setLoggedIn] = useState(false);
  const [apiResponse, setApiResponse] = useState("");

  useEffect(() => {
    const checkSession = async () => {
      try {
        const response = await fetch("http://localhost:8000/check-session", {
          credentials: "include",
        });
        if (response.ok) {
          setLoggedIn(true);
        } else {
          setLoggedIn(false);
        }
      } catch (error) {
        console.error("Error checking session:", error);
        setLoggedIn(false);
      }
    };

    checkSession();
  }, []);
  const onClick = async () => {
    if (loggedIn) {
      try {
        await fetch("http://localhost:8000/logout", {
          method: "POST",
          credentials: "include",
        });
        setLoggedIn(false);
      } catch (error) {
        console.error("Error logging out:", error);
      }
      return;
    }

    const verifier = generateCodeVerifier();
    sessionStorage.setItem("code_verifier", verifier);
    const challenge = await generateCodeChallenge(verifier);

    const authUrl = `https://dev-ptqk6ibc8njgm5ty.us.auth0.com/authorize?response_type=code&client_id=xmPoVoVk6WrffxGwPhDyOVUB3uhuDqre&state=12345&redirect_uri=http://localhost:3000/redirect&code_challenge=${challenge}&code_challenge_method=S256&prompt=login`;
    window.location.href = authUrl;
  };

  const apiProtected = async () => {
    try {
      const response = await fetch("http://localhost:8000/protected", {
        credentials: "include"
      });
      const json = await response.json();
      setApiResponse(json);
      console.log("response-get::", json);
    }
    catch (error) {
      console.log(error);
    }

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
  const isRequestSent = useRef(false);

  useEffect(() => {
    const query = new URLSearchParams(location.search);
    const code = query.get("code");
    const codeVerifier = sessionStorage.getItem("code_verifier");

    if (code && codeVerifier && !isRequestSent.current) {
      isRequestSent.current = true;

      fetch("http://localhost:8000/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          grant_type: "authorization_code",
          redirect_uri: "http://localhost:3000/redirect",
          client_id: "xmPoVoVk6WrffxGwPhDyOVUB3uhuDqre",
          client_secret: "0F0Kn0j_SrecdoUrzHVFgXKWA-qE4BBOxdvDbTrGGllGmVSNgmKyLGVjI7WfaWzT",
          code_verifier: codeVerifier,
          code: code,
        }),
        credentials: "include"
      })
        .then(response => response.json())
        .then(data => {
          // if (!data.error) {
            sessionStorage.removeItem("code_verifier");
            navigate("/");
          // }
        })
        .catch(error => {
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