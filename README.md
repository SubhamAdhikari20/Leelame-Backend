# 🔧 Leelame — Backend

> Backend API for **Leelame**, the online auction and bidding platform.  
> Built with **Node.js**, **Express.js**, and **MongoDB**. Responsible for authentication, auctions, bids, and extension points for AI features (price prediction, fraud detection).

---

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license) [![Node.js](https://img.shields.io/badge/node-%3E%3D16-brightgreen)](#) [![Express](https://img.shields.io/badge/framework-express-000000)](#)

---

## 🚀 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Tech Stack](#tech-stack)
- [Folder Structure](#folder-structure)
- [Environment Variables](#environment-variables)
- [Installation & Setup](#installation--setup)
- [Run & Debug](#run--debug)
- [API Reference](#api-reference)
- [Authentication](#authentication)
- [Database & Models](#database--models)
- [AI Integration](#development-notes)

---

## 🔎 Overview

This backend provides RESTful JSON APIs for:

- User registration, authentication, profiles
- Auction item CRUD
- Bidding workflows (place bid, retrieve bids)
- Admin endpoints (manage auctions, flag abuse)
- WebSocket endpoint (or façade) for real-time updates (optional)
- Hooks/worker endpoints for AI modules (price predictions, fraud scoring)

---

## ✨ Key Features

- RESTful API patterns & clear route separation
- JWT-based authentication & protected routes
- Bid validation & business logic (highest-bid wins)
- MongoDB (Mongoose) models for Users, Items, Bids
- Scalable controllers & middleware architecture
- Ready extension points for AI microservices (HTTP or message queue)

---

## 🧰 Tech Stack

- **Node.js** (runtime)
- **Express.js** (server & routing)
- **MongoDB** (database) + **Mongoose** (ODM)
- **JWT** (authentication)
- **bcrypt** (password hashing)
- **nodemon** (dev restart)
- Optional: **Socket.IO** (real-time), **BullMQ / RabbitMQ** (background jobs), external AI microservice

---

## 📁 Folder Structure

backend/
├─ src/
│ ├─ controllers/ # controllers: auth, user, item, bid
│ ├─ models/ # mongoose schemas
│ ├─ routes/ # route definitions
│ ├─ middleware/ # auth, errorHandler, validation
│ ├─ services/ # business services (email, ai-integration)
│ ├─ utils/ # helpers (logger, validators)
│ ├─ jobs/ # background jobs (optional)
│ ├─ app.js # express app (middleware, routes)
│ └─ server.js # db connect + app listen
├─ .env
├─ package.json
└─ README.md


---

## 🔒 Environment Variables

Copy `.env.example` → `.env` and fill values:

PORT=5000
MONGODB_URI=mongodb+srv://<user>:<pass>@cluster0.mongodb.net/leelame
JWT_SECRET=your_jwt_secret_here



> Keep secrets out of version control. Use secrets manager for production.

---

## 🛠 Installation & Setup

```bash
# 1. Clone repo
git clone https://github.com/<your-username>/leelame-backend.git
cd leelame-backend

# 2. Install dependencies
npm install

# 3. Create .env (see above)
cp .env.example .env

# 4. Start MongoDB (local or use Atlas)
# 5. Start server (development)
npm run dev
```
---

## ▶️ Run & Debug

npm run dev — Start dev server with nodemon (auto-restart).

npm start — Start production server (node).

npm run test — Run tests (if present).

Use debugger or console logs and Postman / Insomnia for endpoint testing.

---

## 📚 API Reference

This is a starter reference — add full request / response examples and error codes in Postman or Swagger later.

### Auth
POST /api/auth/register — register { name, email, password }
POST /api/auth/login — login { email, password } → returns JWT

### Users
GET /api/users/me — get profile (auth)
PUT /api/users/me — update profile (auth)

### Auctions / Items
GET /api/items — list items (query: ?page=&limit=&q=&sort=)
GET /api/items/:id — item detail
POST /api/items — create item (auth, seller)
PUT /api/items/:id — update item (auth, owner)
DELETE /api/items/:id — delete item (auth, owner)

### Bids
GET /api/items/:id/bids — get bid history for an item
POST /api/items/:id/bids — place a bid { amount } (auth)
PUT /api/bids/:id — (optional) modify bid (conditions apply)
DELETE /api/bids/:id — withdraw bid (conditions apply)

---

## 🔐 Authentication

JWT-based auth: tokens delivered on login and sent in Authorization: Bearer <token> header.

Passwords hashed with bcrypt before storing.

Protect routes with an auth middleware that verifies tokens and attaches req.user.

---

## 🗂 Database & Models

User: { name, email (unique), passwordHash, role, createdAt }

AuctionItem: { title, description, images[], startingPrice, currentPrice, sellerId, endAt, status }

Bid: { itemId, bidderId, amount, createdAt }

### Indexes:

Add index on AuctionItem.endAt for fast queries of active auctions.

Add indexes on Bid.itemId and Bid.createdAt for bid history queries.

---

## 🧪 Testing & Validation

Validate incoming requests (Zod or Joi) in routes/middleware.

Unit test controllers & services; integration tests for route flows.

Consider E2E tests for critical flows (signup, list item, place bid, auction close).

---

## 🧵 AI Integration

Keep AI functionality in separate microservice / worker if heavy compute is needed.

### Example flows:

Price Prediction: frontend requests predictedPrice for an item → backend proxies to AI service or returns cached result.

Fraud Detection: background job analyzes bidding patterns, flags suspicious accounts, or sets item.fraudScore.

Communicate between services via REST, gRPC, or message queue (e.g., Redis / BullMQ) for scalability.

---