# BypassBurrito Burp Suite Extension

Burp Suite Pro extension for BypassBurrito - an LLM-powered WAF bypass generator.

## Features

- **Right-click Integration**: Send any request to BypassBurrito with a right-click
- **Quick Bypass**: One-click SQLi, XSS, CMDi, and Path Traversal bypass testing
- **WAF Detection**: Detect and fingerprint WAFs directly from Burp
- **Real-time Results**: View bypass progress and results in a dedicated tab
- **Issue Reporting**: Successful bypasses are automatically reported as Burp Scanner issues
- **Pattern Learning**: Leverages BypassBurrito's learning system for improved bypass rates

## Requirements

- Burp Suite Professional 2023.12 or later
- Java 17 or later
- BypassBurrito server running (`burrito serve`)

## Installation

### Building from Source

1. Ensure you have Maven and Java 17+ installed
2. Navigate to the extension directory:
   ```bash
   cd burp-extension
   ```
3. Build the extension:
   ```bash
   mvn clean package
   ```
4. The JAR file will be created at `target/bypassburrito-burp-1.0.0.jar`

### Loading in Burp Suite

1. Open Burp Suite Professional
2. Go to **Extensions** > **Installed**
3. Click **Add**
4. Select the JAR file: `bypassburrito-burp-1.0.0.jar`
5. The extension will load and add a "BypassBurrito" tab

## Usage

### Starting the Server

Before using the extension, start the BypassBurrito server:

```bash
# Start on default port (8089)
burrito serve

# With authentication
burrito serve --auth-token "your-secret-token"

# Custom port
burrito serve --port 9000
```

### Configuring the Extension

1. Go to the **BypassBurrito** tab in Burp
2. Click the **Configuration** sub-tab
3. Enter the server URL (default: `http://localhost:8089`)
4. Enter the auth token if configured
5. Click **Test Connection** to verify

### Sending Requests for Bypass Testing

#### Method 1: Right-click Menu
1. Find a request in Proxy History, Repeater, or anywhere in Burp
2. Right-click the request
3. Select **BypassBurrito** > **Send to Bypass Generator**
4. Configure the bypass options:
   - Select the parameter to test
   - Choose the attack type
   - Optionally add a custom payload
5. Click **Start Bypass**

#### Method 2: Quick Bypass
1. Right-click any request
2. Select **BypassBurrito** > **Quick Bypass** > **[Attack Type]**
3. The bypass will start immediately using the first parameter

### Viewing Results

1. Go to the **BypassBurrito** tab
2. The **Results** sub-tab shows all bypass attempts
3. Double-click any row to see full details
4. Successful bypasses are also reported as Burp Scanner issues

### WAF Detection

1. Right-click any request
2. Select **BypassBurrito** > **Detect WAF**
3. A dialog will show the detected WAF type and confidence

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Burp Suite Pro                           │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              BypassBurrito Extension                   │  │
│  │  • Context Menu (right-click)                         │  │
│  │  • Custom Tab (Results, Queue, Config, Log)           │  │
│  │  • Issue Reporter (Scanner integration)               │  │
│  └───────────────────────────────────────────────────────┘  │
│                            │                                 │
│                    REST API (HTTP/JSON)                      │
└────────────────────────────┼─────────────────────────────────┘
                             │
              ┌──────────────▼──────────────┐
              │      BypassBurrito Server   │
              │    (burrito serve --port)   │
              │                             │
              │  • LLM-powered mutations    │
              │  • WAF detection            │
              │  • Pattern learning         │
              │  • Genetic evolution        │
              └─────────────────────────────┘
```

## API Endpoints Used

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/bypass` | Submit a bypass request |
| GET | `/api/v1/bypass/:id` | Get bypass status/result |
| DELETE | `/api/v1/bypass/:id` | Cancel a bypass job |
| POST | `/api/v1/detect` | Detect WAF on a target |
| GET | `/api/v1/queue` | List queued/running jobs |
| GET | `/api/v1/patterns` | Get learned patterns |
| GET | `/api/v1/health` | Health check |

## Troubleshooting

### "Failed to connect to server"
- Ensure BypassBurrito server is running: `burrito serve`
- Check the server URL in Configuration tab
- Verify firewall allows connection to the port

### "No parameters found in request"
- The selected request has no URL or body parameters
- Try adding a test parameter to the URL: `?test=value`

### Bypasses not appearing as issues
- Ensure "Report as Issues" is enabled in configuration
- Only successful bypasses are reported as issues

### Extension not loading
- Verify you're using Burp Suite Professional (not Community)
- Check Java version: `java -version` (need 17+)
- Check Burp's error log for details

## Development

### Project Structure

```
burp-extension/
├── pom.xml                          # Maven build configuration
├── README.md                        # This file
└── src/main/java/com/bypassburrito/burp/
    ├── BurritoExtension.java        # Main extension entry point
    ├── BurritoApiClient.java        # REST API client
    ├── BurritoContextMenu.java      # Right-click menu provider
    ├── BurritoHttpHandler.java      # HTTP interception handler
    ├── BurritoIssueReporter.java    # Burp issue reporter
    ├── BurritoBypassRequest.java    # Request model
    ├── BurritoBypassResult.java     # Result model
    └── ui/
        └── BurritoTab.java          # Main UI tab
```

### Building for Development

```bash
# Compile
mvn compile

# Package
mvn package

# Clean and rebuild
mvn clean package
```

## License

Part of the BypassBurrito project.
