# 🗡️ SQLBurp

![Java](https://img.shields.io/badge/java-17+-blue?logo=java&logoColor=white)
![Burp Suite](https://img.shields.io/badge/Burp_Suite-Extension-orange)
![sqlmap](https://img.shields.io/badge/sqlmap-REST%20API-red)

A Burp Suite extension that integrates the sqlmap REST API into your testing workflow. Send requests from anywhere in Burp, track multiple scans concurrently, and review persisted results. All scan data is stored directly in the Burp project file with no external database required.

<img width="1446" height="725" alt="image" src="https://github.com/user-attachments/assets/8ea98fcc-a1b1-4d1b-9380-00eeeb113d54" />

<img width="1446" height="725" alt="image" src="https://github.com/user-attachments/assets/cb8e8818-9b3a-4b09-a839-f8a755a24764" />

## 🚀 Setup

**1. Download the jar**

Download the latest `SQLBurp.jar` from the [Releases](../../releases) page.

**2. Start the sqlmap REST API**

```bash
python sqlmapapi.py -s -H 127.0.0.1 -p 8775
```

No `--database` flag needed.

**3. Load the extension**

`Extensions` -> `Add` -> `Extension Type: Java` -> select `SQLBurp.jar`.

The **SQLBurp** tab will appear. Use the **Ping** button to verify the API is reachable.

## 📖 Usage

### Sending a request

Right-click any request in Proxy, Repeater, Target, or anywhere else in Burp and select **Send to SQLMap API**. The scan is submitted immediately using the current Options tab settings.

### ⚡ Options tab

The Options tab is split into four sections.

#### Core Options

| Setting | Description |
| --- | --- |
| API URL | Address of the running sqlmapapi server |
| Level | Detection level (1-5) |
| Risk | Risk level (1-3) |
| Threads | Concurrent HTTP requests (1-10) |
| Technique | SQLi techniques to test (e.g. `BEUSTQ`) |
| DBMS | Force a specific backend, or leave as `(auto)` |
| Tamper | Comma-separated tamper scripts (e.g. `space2comment,randomcase`) |
| Poll (s) | How often to poll for status updates |

#### Extra sqlmap Arguments

A free-form text field for passing additional sqlmap flags that aren't exposed in the UI. Flags are parsed and mapped to their correct sqlmapapi JSON keys, so they are actually applied to the scan.

Supported flags include:

| Flag | Description |
| --- | --- |
| `--delay=N` | Seconds to wait between each HTTP request |
| `--timeout=N` | Seconds before a request times out |
| `--retries=N` | Number of retries on connection timeout |
| `--time-sec=N` | Seconds to delay for time-based blind injection |
| `--proxy=URL` | Route requests through a proxy |
| `--proxy-cred=user:pass` | Proxy authentication credentials |
| `--user-agent=UA` | Custom User-Agent header |
| `--referer=URL` | Custom Referer header |
| `--cookie=COOKIE` | Custom cookie string |
| `--headers=HEADERS` | Extra HTTP headers |
| `--auth-type=TYPE` | HTTP authentication type (Basic, Digest, NTLM) |
| `--auth-cred=user:pass` | HTTP authentication credentials |
| `--tor` | Route through Tor |
| `--tor-type=TYPE` | Tor proxy type |
| `--tor-port=N` | Tor proxy port |
| `--ignore-proxy` | Ignore system proxy settings |
| `--ignore-redirects` | Ignore redirects |
| `--ignore-timeouts` | Ignore connection timeouts |
| `--force-ssl` | Force HTTPS |
| `--flush-session` | Clear session data and re-test |
| `--fresh-queries` | Ignore cached query results |
| `--mobile` | Emulate a mobile User-Agent |
| `--prefix=STR` | Injection payload prefix |
| `--suffix=STR` | Injection payload suffix |
| `--safe-url=URL` | URL to visit periodically during testing |
| `--text-only` | Compare pages based on text content only |

**Example:** `--delay=2 --timeout=30 --proxy=http://127.0.0.1:8080`

Unknown flags are silently ignored.

#### Flags

| Flag | Description |
| --- | --- |
| Batch | Non-interactive mode (sqlmap uses its own defaults for any prompts) |
| Random Agent | Randomise the User-Agent header |
| Forms | Discover and test forms on the target page |
| Enum DBs | Enumerate databases on injection confirmation |
| Current User | Retrieve the current database user |
| Banner | Retrieve the DBMS banner |
| Is DBA | Check whether the current user has DBA privileges |

#### Prompt Answers

Only visible when **Batch** is unchecked. Lets you pre-configure sqlmap's response to known interactive prompts. Each prompt can be set to **Yes**, **No**, or **Default** (sqlmap's own built-in default for that prompt).

| Prompt | Description |
| --- | --- |
| Crack found hashes | Attempt to crack any discovered password hashes |
| Dictionary-based hash attack | Use a wordlist for hash cracking |
| Store hashes to CSV file | Save discovered hashes to a file |
| Use common password suffixes | Append common suffixes during hash cracking |
| Quit after finding first injection | Stop testing once one injectable parameter is found |
| Merge scan results | Merge results from multiple runs |
| Flush session and re-test | Clear cached session data and restart testing |
| Retrieve full schema | Enumerate the full database schema |
| Adjust level/risk for WAF detection | Automatically increase level/risk if a WAF is detected |
| Skip testing other parameters | Stop after the first vulnerable parameter is confirmed |

Settings are snapshotted at submission time, so each scan row remembers the exact options it was run with. Changing the panel after submission does not affect running scans.

### 📊 Scans tab

The Scans tab contains the scan table and log output. Each submitted request appears as a row. Columns are sortable. Click any row to view its live log and option snapshot in the detail panel below.

| Status | Meaning |
| --- | --- |
| Queued | Submitted, not yet started |
| Running | Actively scanning |
| Finished | Completed, no injections found |
| Vulnerable | Injection confirmed |
| Stopped | Manually stopped |
| Error | Scan failed |

### 🖱️ Right-click menu

| Action | Description |
| --- | --- |
| Stop Task | Sends a stop signal to sqlmapapi and marks the scan as Stopped |
| Delete Task | Stops the scan, deletes it from the API, and removes all persisted data |

### 🧰 Toolbar

| Button | Description |
| --- | --- |
| Stop All | Stops all currently running scans |
| Remove Finished | Removes all Finished, Stopped, and Error rows and purges their data |

## 💾 Persistence

All scan data is stored in the Burp project file via the Montoya API's `persistence().extensionData()`. This is natively project-scoped, so opening a different Burp project shows only that project's scans with no cross-contamination between engagements.

- **No external database** - sqlmapapi can be restarted freely without losing any scan history.
- **Incremental saving** - the scan record is written on start and updated on every log line, so data is preserved even if Burp is closed mid-scan.
- **Automatic restore** - all scans for the current project are loaded back into the table when the extension initialises.

De-selecting a scan or using "Remove Finished" purges it from both the API and the project permanently.

## 🗄️ Request Repository

SQLBurp captures all incoming proxy requests automatically, regardless of Burp Target Scope, filtering out static assets (images, CSS, JS). This allows you to collect a rich repository of requests as you browse the target application.

From the **Request Repository** tab you can:
- Review request and response contents natively.
- Use the **Mark Injection Points** tools to manually define custom injection markers (`*`) in specific areas (Headers, Cookies, Body, User-Agent) before sending them to sqlmap.
- Dispatch requests to the API sequentially or in parallel.

## 🛠️ Helper Script

For your convenience, a universal `.bat` file is included (`start_sqlmap_api.bat`). Simply place it in the same directory as your `sqlmap.py` script and run it to easily launch the REST API server with the required configuration and credentials for SQLBurp.

## 📝 Notes

- The extension deduplicates requests, so sending the same request multiple times in a single action will only create one scan.
- HTTPS targets are detected automatically from the HTTP service; `forceSSL` is set accordingly.
- For scans that were still running when the extension was last closed, the extension will attempt to reconnect to the live API on load. If the API has been restarted in the interim, those scans will show their last known status.
- DEBUG-level log entries from sqlmap are filtered out of the log view to keep output readable.

## 🔨 Building from source

### Requirements

- [Java JDK](https://www.oracle.com/java/technologies/downloads/) (JDK 17 or later)
- [sqlmap](https://github.com/sqlmapproject/sqlmap) installed and accessible
- Gradle (install via [Scoop](https://scoop.sh) on Windows)

### Build

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
irm get.scoop.sh | iex
scoop install gradle
```

Then in the project folder:

```powershell
gradle wrapper
.\gradlew.bat jar
```

The jar is output to `build\libs\SQLBurp.jar`.