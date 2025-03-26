# Mock Server Mode

For local development and testing, you can run the application in mock mode, which uses in-memory data instead of connecting to a MongoDB database.

## Steps to run in mock mode:

1. Install dependencies:
   ```
   npm install
   ```

2. Copy the mock environment template:
   ```
   cp .env.mock .env
   ```

3. Run the server in mock mode:
   ```
   npm run mock
   ```

The server will start on the configured port (default: 3001) and use in-memory mock data for all database operations.

## Mock credentials:

### Without MFA enabled
- Email: user1@example.com
- Password: password-hash-1

### With MFA enabled
- Email: user2@example.com 
- Password: password-hash-2 