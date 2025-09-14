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

## Two-Factor Authentication (2FA)

### Overview
The solution implements two-factor authentication (2FA) using the TOTP (Time-based One-Time Password) protocol. This method adds an extra layer of security by requiring a one-time code in addition to the password.

### Features
- **Easy Setup**: QR code for quick configuration with authenticator apps
- **Compatible Apps**: Google Authenticator, Microsoft Authenticator, Authy, etc.
- **Backup Codes**: Generation of recovery codes for emergency access
- **Toggle Capability**: Users can enable/disable 2FA at any time
- **Persistent State**: 2FA status is remembered across sessions

### Authentication Flow
1. User logs in with email/password
2. If 2FA is enabled, user is redirected to 2FA verification screen
3. User enters the 6-digit code from their authenticator app
4. Once verified, full access is granted

### Initial Setup
1. Navigate to your account security settings
2. Click on "Enable 2FA"
3. Scan the QR code with your authenticator app
4. Enter the generated code to confirm setup
5. Store backup codes in a secure location

---

## Objectives

- Provide a minimal yet secure authentication system using modern standards (JWT, RSA).
- Enable secure frontend/backend communication with cookie + token handling.
- Serve as a clean starting point for fullstack apps requiring protected APIs.