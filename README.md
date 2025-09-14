# ASP.NET + React Auth Boilerplate

## Overview

**ASP.NET + React Auth Boilerplate** is a fullstack starter kit combining **ASP.NET Core 8 (API)** and **React (frontend)**. It provides a secure, production-ready authentication system using **JWT (RSA-signed)**, **refresh tokens**, **role-based access**, and **CSRF protection**. Designed to be a clean foundation for any project that requires user authentication and protected API routes.

---

## Features

- **JWT Authentication**: Stateless access tokens with short lifespan, RSA-signed for security.
- **Refresh Tokens**: Automatically renews access tokens using secure HttpOnly cookies.
- **2FA**: Two-factor authentication with TOTP and email options.
- **Social Login**: Sign in with Google authentication integration.
- **CSRF Protection**: Built-in anti-forgery token system for cookie-based routes.
- **Email Confirmation**: New users must verify their email before logging in and forgotten password.
- **Role-Based Authorization**: Easily restrict access to routes (`User`, `Admin`).
- **Secure Logout**: Tokens are invalidated and removed from the database.
- **Frontend Integration**: React client and CSRF-aware requests.
- **Form Validation**: Enforces strong password policies and input formats.
- **Extensible**: Add your own domain logic, UI components, or data models easily.
- **Error Handling**: Comprehensive error messaging and user feedback.
- **Logging**: Structured logging with Serilog integration.

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

- Implement a comprehensive authentication system using modern security standards (JWT, RSA).
- Provide multiple authentication methods including email/password, social login, and 2FA.
- Ensure secure frontend/backend communication with cookie handling and CSRF protection.
- Maintain high security standards with features like email verification and strong password policies.
- Enable flexible access control through role-based authorization.
- Implement secure session management with refresh tokens and secure logout.
- Provide comprehensive error handling and user feedback.
- Ensure system observability through structured logging.
- Create an extensible foundation for building secure fullstack applications.