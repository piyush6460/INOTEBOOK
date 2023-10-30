import React, { useState } from "react";
import "./App.css";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import NoteState from "./context/notes/NoteState";
import { Navbar } from "./navbar/Navbar";
import Alert from "./components/Alert";
import { Home } from "./components/Home";
import { About } from "./components/About";
import Register from "./components/Register";
import Login from "./components/Login";

function App() {
  const [alert, setAlert] = useState(null);
  const toggleAlert = (message, type) => {
    setAlert({
      msg: message,
      type: type,
    });
    setTimeout(() => {
      setAlert(null);
    }, 1500);
  };
  return (
    <>
      <div className="app">
        <NoteState>
          <Router>
            <Navbar />
            <Alert alert={alert} />
            <div className="container py-5 my-auto">
              <Routes>
                <Route path="/" element={<Home toggleAlert={toggleAlert} />} />
                <Route path="/about" element={<About />} />
                <Route
                  path="/createuser"
                  element={<Register toggleAlert={toggleAlert} />}
                />
                <Route
                  path="/login"
                  element={<Login toggleAlert={toggleAlert} />}
                />
              </Routes>
            </div>
          </Router>
        </NoteState>
      </div>
    </>
  );
}

export default App;
