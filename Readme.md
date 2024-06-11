# ZeroSafer

This is a simple authentication system based on the Schnorr signature scheme implemented using Python and Tkinter GUI library.

## Requirements

- Python 3.x
- Tkinter
- sympy
- secrets
- hashlib
- sqlite3

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/missreyyo/TC_security.git
    ```

2. Navigate to the project directory:
    ```bash
    cd schnorr-authentication
    ```

3. Install the dependencies:

```bash
pip install tkinter sympy secrets hashlib sqlite3
```
## Usage

1. Run the application:
    ```bash
    python app.py
    ```

2. Two tabs will be displayed:
    - **Register**: Allows users to register with their TC ID and username.
    - **Authenticate**: Allows registered users to authenticate with their TC ID, username, and secret key.

3. To register:
    - Enter your TC ID and username.
    - Click on the **Register** button.
    - Save the secret key displayed in the text area.

4. To authenticate:
    - Enter your TC ID, username, and secret key.
    - Click on the **Authenticate** button.
    - A message box will appear indicating whether the authentication was successful or not.

## Database

The application uses an SQLite database named `authentication.db` to store user information.

## Security

- The Schnorr signature scheme is used for authentication, providing security against various attacks.
- User information such as TC ID and username are hashed using SHA-256 before storing them in the database.
## Functions

### `register()`

- Used to register a user.
- Validates the entered TC ID and username.
- If valid, generates Schnorr keys and saves the user.
- Displays the saved keys to the user.

### `authenticate()`

- Used for user authentication.
- Validates the entered TC ID, username, and secret key.
- If valid, performs Schnorr identity verification and notifies the user of the result.

### `is_tc_registered(hashed_tc)`

- Checks if the specified TC ID is registered in the database.

### `is_username_registered(hashed_username)`

- Checks if the specified username is registered in the database.

### `save_user(hashed_tc, hashed_username, public_key, g, p)`

- Saves a new user to the database.

## Database Structure

The application uses an SQLite database named `authentication.db` with the following table structure:

- **users**:
  - **id**: INTEGER PRIMARY KEY AUTOINCREMENT
  - **hashed_tc**: TEXT (UNIQUE)
  - **hashed_username**: TEXT (UNIQUE)
  - **public_key**: TEXT
  - **g**: TEXT
  - **p**: TEXT

This table stores user information including hashed TC ID, hashed username, public key, and parameters `g` and `p` required for the Schnorr signature scheme.