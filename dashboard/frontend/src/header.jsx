import React from 'react';
import { Container, Nav, Navbar, NavDropdown } from 'react-bootstrap';
import { NavLink, useNavigate } from 'react-router-dom';
import './header.css';

function Header() {
  const navigate = useNavigate();

  return (
    <Navbar expand="lg" variant="dark" className="secure-navbar sticky-top">
      <Container fluid className="secure-navbar-inner">
        <Navbar.Brand className="secure-brand" onClick={() => navigate('/')}>
          Secureflow AI
        </Navbar.Brand>

        <Navbar.Toggle aria-controls="secure-navbar-nav" className="secure-toggler" />

        <Navbar.Collapse id="secure-navbar-nav">
          <Nav className="me-auto secure-nav-links">
            <Nav.Link as={NavLink} to="/" end className="secure-nav-link">
              Home
            </Nav.Link>
            <Nav.Link as={NavLink} to="/dashboard" className="secure-nav-link">
              Dashboard
            </Nav.Link>

            <NavDropdown title="Operations" id="operations-dropdown" className="secure-dropdown">
              <NavDropdown.Item as={NavLink} to="/traffic">
                Real-Time Traffic
              </NavDropdown.Item>
              <NavDropdown.Item as={NavLink} to="/blocked-ips">
                Blocked IP Intelligence
              </NavDropdown.Item>
              <NavDropdown.Item as={NavLink} to="/analytics">
                Attack Analytics
              </NavDropdown.Item>
            </NavDropdown>
          </Nav>

          <Nav className="secure-nav-links secure-auth-links">
            <Nav.Link as={NavLink} to="/login" className="secure-nav-link auth-link">
              Login
            </Nav.Link>
            <Nav.Link as={NavLink} to="/register" className="secure-nav-link auth-link highlight">
              Register
            </Nav.Link>
          </Nav>
        </Navbar.Collapse>
      </Container>
    </Navbar>
  );
}

export default Header;
