# ASP.NET + React Auth Boilerplate

## Overview

**ASP.NET + React Auth Boilerplate** is a fullstack starter kit combining **ASP.NET Core 8 (API)** and **React (frontend)**. It provides a secure, production-ready authentication system using **JWT (RSA-signed)**, **refresh tokens**, **role-based access**, and **CSRF protection**. Designed to be a clean foundation for any project that requires user authentication and protected API routes.

---

## Features

- **JWT Authentication**: Stateless access tokens with short lifespan, RSA-signed for security.
- **Refresh Tokens**: Automatically renews access tokens using secure HttpOnly cookies.
- **CSRF Protection**: Built-in anti-forgery token system for cookie-based routes.
- **Email Confirmation**: New users must verify their email before logging in.
- **Role-Based Authorization**: Easily restrict access to routes (`User`, `Admin`).
- **Secure Logout**: Tokens are invalidated and removed from the database.
- **Frontend Integration**: React client with Axios and CSRF-aware requests.
- **Form Validation**: Enforces strong password policies and input formats.
- **Extensible**: Add your own domain logic, UI components, or data models easily.

---

## Technologies Used

- **Backend**: ASP.NET Core 8 + Identity
- **Frontend**: React (Vite)
- **Authentication**: JWT (RSA), Refresh Tokens
- **Database**: Entity Framework Core (SQL Server)
- **Email**: SMTP for account confirmation
- **Security**: CSRF, HttpOnly cookies, SameSite policies

---

## Objectives

- Provide a minimal yet secure authentication system using modern standards (JWT, RSA).
- Enable secure frontend/backend communication with cookie + token handling.
- Serve as a clean starting point for fullstack apps requiring protected APIs.