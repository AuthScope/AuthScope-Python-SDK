# AuthScope Python SDK

A Python SDK for integrating AuthScope authentication and license management into your applications. AuthScope provides secure, cryptographically verified authentication with offline support and hardware-based validation.

## Features

- **Secure Authentication**: ECDSA signature verification with SHA-256
- **License Management**: License key-based authentication and subscription tracking
- **Offline Support**: Cached credentials for offline access when the server is unavailable
- **Hardware Binding**: Hardware ID (HWID) detection to prevent license abuse
- **Cross-Platform**: Windows support with extensible design for other platforms
- **Session Management**: Token-based session handling

## Installation

### Requirements

- Python 3.7+
- `requests` - HTTP library for API communication
- `cryptography` - For cryptographic operations
- `pywin32` - For Windows-specific operations (Windows only)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/AuthScope-Python-SDK.git
cd AuthScope-Python-SDK
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Quick Start

```python
from AuthScope import AuthClient

# Initialize the auth client
auth = AuthClient(
    appID="your_app_id",
    version="1.0.0",
    publicKey="your_public_key_string",
    base_url="https://your-auth-server.com/api/authenticate"  # Optional
)

# Check if running in offline mode
if not auth.offline_mode:
    # Prompt for license key and authenticate
    auth.license(input("Enter license key: "))
else:
    print("Running in offline mode")

# Access user information
print(f"Username: {auth.user_data.username}")
print(f"User ID: {auth.user_data.user_id}")
print(f"Subscription: {auth.user_data.subscription}")
print(f"Client IP: {auth.user_data.client_ip}")
print(f"Last Login: {auth.user_data.last_login}")
```

## API Reference

### AuthClient

The main class for managing authentication and user sessions.

#### Constructor

```python
AuthClient(appID, version, publicKey, base_url=None)
```

**Parameters:**
- `appID` (str): Your application ID
- `version` (str): Your application version
- `publicKey` (str): Base64-encoded ECDSA public key for signature verification
- `base_url` (str, optional): Custom authentication server URL. Defaults to `https://auth-scope.onrender.com/api/authenticate`

#### Methods

##### `init()`
Initializes the authentication client by contacting the server and obtaining a session token. Called automatically in the constructor. Falls back to offline login if the server is unreachable.

##### `license(key)`
Authenticates using a license key.

**Parameters:**
- `key` (str): The license key to authenticate with

**Behavior:**
- Validates the license with the server
- Saves offline login data to cache if available
- Populates user data
- Falls back to offline login on connection failure

##### `user_login(username, password)`
Authenticates using username and password credentials.

**Parameters:**
- `username` (str): The user's username
- `password` (str): The user's password

**Behavior:**
- Authenticates the user with their credentials
- Saves offline login data to cache if available
- Populates user data
- Falls back to offline login on connection failure

##### `register(username, password)`
Creates a new user account.

**Parameters:**
- `username` (str): Desired username for the new account
- `password` (str): Password for the new account

**Returns:**
- dict: Response data from the server

**Behavior:**
- Creates a new user account with the provided credentials
- Automatically logs in the user after successful registration
- Populates user data
- Exits on registration failure or connection error

##### `validate_session()`
Validates the current session token.

**Returns:**
- bool: `True` if session is valid, `False` otherwise

**Behavior:**
- Checks if the current session token is still valid with the server
- Updates user data if validation succeeds
- Returns `False` on connection failure without exiting

##### `upgrade(subscription_plan)`
Upgrades the user's subscription plan.

**Parameters:**
- `subscription_plan` (str): The target subscription plan to upgrade to

**Returns:**
- dict: Response data from the server

**Behavior:**
- Upgrades the user's subscription to the specified plan
- Updates user data with new subscription information
- Exits on upgrade failure or connection error

##### `logout()`
Clears the current session and user data.

**Behavior:**
- Notifies the server of the logout (if online)
- Clears all session information locally
- Gracefully continues even if server is unreachable
- Clears cached user data

### UserData

Accessible via `auth.user_data`, contains the following attributes:

- `user_id` (str): Unique user identifier
- `username` (str): The username
- `subscription` (str): Subscription type or tier
- `created_at` (str): ISO format creation timestamp
- `last_login` (str): ISO format last login timestamp
- `client_ip` (str): Client's IP address

### AuthClient Properties

- `initialized` (bool): Whether the client has been initialized
- `offline_mode` (bool): Whether currently operating in offline mode
- `sessionid` (str): Current session token

## Offline Mode

The SDK automatically falls back to offline mode when the authentication server is unavailable. Cached credentials are stored locally and validated using the same cryptographic signature verification as online authentication.

### Cache Details

- **Location**: `~/.authscope_cache/{appID}.json`
- **Default TTL**: 7 days (configurable)
- **Validation**: Hardware ID, signature, version, and timestamp consistency

## Security Considerations

1. **Public Key Storage**: The public key is included in your application and is not secret
2. **Hardware ID**: Prevents license sharing across different computers
3. **Signature Verification**: All responses are cryptographically verified
4. **Version Mismatch**: Offline cache is rejected if app version differs
5. **Clock Drift Detection**: System clock rollback is detected and rejected
6. **Timestamp Consistency**: User creation timestamp is validated against server timestamp

## Error Handling

The SDK exits with code 1 on critical errors:

- Signature verification failure
- Server errors (when online)
- Invalid offline cache
- Version mismatch
- HWID mismatch
- Expired credentials
- System clock issues

## Platform Support

### Windows
Fully supported with hardware ID detection.

### Other Platforms
The `others.get_hwid()` function returns `"unsupported"` on non-Windows platforms. Extend the implementation for your target platform as needed.

## Examples

### Example 1: License-Based Authentication

Authenticate users with a license key.

```python
from AuthScope import AuthClient

# Initialize the client
auth = AuthClient(
    appID="MyApp",
    version="1.0.0",
    publicKey="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
)

# Check if offline mode (no server available)
if auth.offline_mode:
    print("Running in offline mode with cached credentials")
else:
    # Authenticate with license key
    license_key = input("Enter your license key: ")
    auth.license(license_key)

# Access user information
print(f"Welcome {auth.user_data.username}!")
print(f"User ID: {auth.user_data.user_id}")
print(f"Subscription: {auth.user_data.subscription}")
print(f"Client IP: {auth.user_data.client_ip}")

# Cleanup
auth.logout()
```

### Example 2: User Registration

Create a new user account and automatically log them in.

```python
from AuthScope import AuthClient

auth = AuthClient(
    appID="MyApp",
    version="1.0.0",
    publicKey="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
)

# Register a new user
try:
    response = auth.register(
        username="alice_smith",
        password="secure_password_123"
    )
    
    print(f"Account created successfully!")
    print(f"Username: {auth.user_data.username}")
    print(f"User ID: {auth.user_data.user_id}")
    print(f"Subscription: {auth.user_data.subscription}")
    
except Exception as e:
    print(f"Registration failed: {e}")

# Cleanup
auth.logout()
```

### Example 3: User Credentials Login

Authenticate using username and password.

```python
from AuthScope import AuthClient

auth = AuthClient(
    appID="MyApp",
    version="1.0.0",
    publicKey="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
)

# Login with username and password
username = input("Enter username: ")
password = input("Enter password: ")

try:
    auth.user_login(username, password)
    print(f"Login successful! Welcome {auth.user_data.username}")
    print(f"Last login: {auth.user_data.last_login}")
except Exception as e:
    print(f"Login failed: {e}")

# Cleanup
auth.logout()
```

### Example 4: Session Validation

Check if the current session is still valid.

```python
from AuthScope import AuthClient

auth = AuthClient(
    appID="MyApp",
    version="1.0.0",
    publicKey="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
)

# Login
auth.user_login("username", "password")

# Validate session after some time
import time
time.sleep(60)

if auth.validate_session():
    print("Session is still valid")
    print(f"Current subscription: {auth.user_data.subscription}")
else:
    print("Session has expired, please login again")

# Cleanup
auth.logout()
```

### Example 5: Subscription Upgrade

Upgrade a user's subscription plan.

```python
from AuthScope import AuthClient

auth = AuthClient(
    appID="MyApp",
    version="1.0.0",
    publicKey="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
)

# Login
auth.user_login("username", "password")

# Check current subscription
print(f"Current subscription: {auth.user_data.subscription}")

# Upgrade to premium
try:
    auth.upgrade("premium")
    print(f"Upgrade successful!")
    print(f"New subscription: {auth.user_data.subscription}")
except Exception as e:
    print(f"Upgrade failed: {e}")

# Cleanup
auth.logout()
```

### Example 6: Complete Application Flow with All Methods

A comprehensive example demonstrating all authentication methods and operations.

```python
from AuthScope import AuthClient

def display_menu():
    print("\n=== AuthScope Demo ===")
    print("1. Register New Account")
    print("2. Login with Credentials")
    print("3. Login with License Key")
    print("4. View User Info")
    print("5. Validate Session")
    print("6. Upgrade Subscription")
    print("7. Logout")
    print("8. Exit")
    return input("Choose option: ")

def main():
    # Initialize the client
    auth = AuthClient(
        appID="MyApp",
        version="1.0.0",
        publicKey="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
    )
    
    # Check offline mode
    if auth.offline_mode:
        print("⚠️  Running in OFFLINE MODE - using cached credentials")
        print(f"Welcome back {auth.user_data.username}!\n")
    
    while True:
        choice = display_menu()
        
        try:
            if choice == "1":
                # Register
                print("\n--- Register New Account ---")
                username = input("Create username: ")
                password = input("Create password: ")
                
                auth.register(
                    username=username,
                    password=password
                )
                print("✓ Registration successful!")
            
            elif choice == "2":
                # User Login
                print("\n--- User Login ---")
                username = input("Username: ")
                password = input("Password: ")
                
                auth.user_login(username, password)
                print("✓ Login successful!")
            
            elif choice == "3":
                # License Login
                print("\n--- License Login ---")
                license_key = input("Enter license key: ")
                
                auth.license(license_key)
                print("✓ License login successful!")
            
            elif choice == "4":
                # View User Info
                print("\n--- User Information ---")
                print(f"Username: {auth.user_data.username}")
                print(f"User ID: {auth.user_data.user_id}")
                print(f"Subscription: {auth.user_data.subscription}")
                print(f"Client IP: {auth.user_data.client_ip}")
                print(f"Created: {auth.user_data.created_at}")
                print(f"Last Login: {auth.user_data.last_login}")
                print(f"Offline Mode: {auth.offline_mode}")
            
            elif choice == "5":
                # Validate Session
                print("\n--- Session Validation ---")
                is_valid = auth.validate_session()
                if is_valid:
                    print("✓ Session is valid")
                else:
                    print("✗ Session is invalid or expired")
            
            elif choice == "6":
                # Upgrade Subscription
                print("\n--- Subscription Upgrade ---")
                print("Available plans: free, basic, premium, enterprise")
                plan = input("Choose subscription plan: ")
                
                auth.upgrade(plan)
                print(f"✓ Upgraded to {plan}!")
            
            elif choice == "7":
                # Logout
                auth.logout()
                print("✓ Logged out successfully!")
            
            elif choice == "8":
                # Exit
                auth.logout()
                print("Goodbye!")
                break
            
            else:
                print("Invalid option")
        
        except KeyboardInterrupt:
            print("\n\nInterrupted by user")
            auth.logout()
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

## License

[Your License Here]

## Support

For issues, questions, or contributions, please open an issue or submit a pull request on GitHub.