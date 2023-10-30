import React from "react";
import { Link, useNavigate } from "react-router-dom";

export const Navbar = () => {
  let navigate = useNavigate();
  const handleLogout = async () => {
    await localStorage.removeItem("myToken");
    await navigate("/login");
  };
  return (
    <div>
      <nav className="navbar navbar-expand-lg bg-dark">
        <div className="container-fluid ">
          <Link className="navbar-brand btn btn-outline-dark text-light" to="/">
            iNotebook
          </Link>
          <button
            className="navbar-toggler bg-primary"
            type="button"
            data-bs-toggle="collapse"
            data-bs-target="#navbarSupportedContent"
            aria-controls="navbarSupportedContent"
            aria-expanded="false"
            aria-label="Toggle navigation">
            <span className="navbar-toggler-icon"></span>
          </button>
          <div className="collapse navbar-collapse" id="navbarSupportedContent">
            <ul className="navbar-nav me-auto mb-lg-0">
              <li className="nav-item">
                <Link
                  className={`nav-link text-light btn btn-outline-primary m-1`}
                  aria-current="page"
                  to="/">
                  Home
                </Link>
              </li>
              <li className="nav-item">
                <Link
                  className={`nav-link text-light btn btn-outline-primary m-1`}
                  to="/about">
                  About
                </Link>
              </li>
            </ul>
            <form className="d-flex">
              {!localStorage.getItem("myToken") ? (
                <div>
                  <Link
                    className="text-light btn btn-primary m-1"
                    to="/createuser"
                    role="button">
                    Register
                  </Link>
                  <Link
                    className="text-light btn btn-primary m-1"
                    to="/login"
                    role="button">
                    Login
                  </Link>
                </div>
              ) : (
                <Link
                  className="text-light btn btn-primary m-1"
                  onClick={handleLogout}
                  role="button">
                  Logout
                </Link>
              )}
            </form>
          </div>
        </div>
      </nav>
    </div>
  );
};
