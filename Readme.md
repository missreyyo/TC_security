# ZeroSafer

This project implements a two-factor authentication (2FA) system using hashed credentials and algorithm-based challenges. Additionally, it allows users to generate, store, and share symmetric keys.

## Features

- User Registration: Register with a TC ID (Turkish Citizenship ID) and a username. Select an algorithm (square root, square, or prime factors) to generate a random number as a challenge.
- Authentication: Authenticate by providing your TC ID, username, and solving the challenge based on the selected algorithm.

- Symmetric Key Management: Generate, store, and send symmetric keys to other registered users. View the symmetric keys you have sent and received.

## Prerequisites

- Python 3.x: Ensure you have Python 3 installed on your system.
- Tkinter: Included with Python's standard library for GUI development.

- SQLite 3: Included with Python's standard library for database management.
- Sympy: A Python library for symbolic mathematics.

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/missreyyo/TC_security.git
   cd two-factor-authentication-system
    ```
## Usage

### Run the Application
```sh
python app.py
```

## Register a User

1. Navigate to the **"Register"** tab.
2. Enter your **TC ID** and **username**.
3. Select an **algorithm**.
4. Click **"Register"**.

## Authenticate a User

1. Go to the **"Authenticate"** tab.
2. Enter your **TC ID** and **username**.
3. Select the **algorithm** used during registration.
4. Enter the **expected value** based on the algorithm.
5. Click **"Authenticate"**.

## Manage Symmetric Keys

1. After authentication, go to the **"Symmetric Key"** tab.
2. **Generate** and **store** a symmetric key.
3. **Send** the symmetric key to another registered user.
4. View your **sent** and **received** symmetric keys.


## Functions

### User Functions

- **`register()`**: Registers a new user with hashed TC ID and username. Generates a random number based on the selected algorithm and stores the user data in the database.
- **`authenticate()`**: Authenticates a user by verifying the hashed TC ID and the provided algorithm input.

### Symmetric Key Functions

- **`generate_and_store_symmetric_key()`**: Generates a random symmetric key and stores it for the authenticated user.
- **`send_symmetric_key()`**: Sends a symmetric key to another registered user.
- **`view_symmetric_keys()`**: Displays the symmetric keys generated and stored by the authenticated user.
- **`view_received_keys()`**: Displays the symmetric keys received from other users.

## Database Structure

### `users` table:
- `id`: INTEGER PRIMARY KEY
- `hashed_tc`: TEXT UNIQUE
- `hashed_username`: TEXT UNIQUE
- `random_number`: INTEGER
- `algorithm`: TEXT

### `symmetric_keys` table:
- `id`: INTEGER PRIMARY KEY
- `sender_hashed_username`: TEXT
- `recipient_hashed_username`: TEXT
- `symmetric_key`: TEXT