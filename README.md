<p align="center">
  
</p>
<p align="center"><h1 align="center">Cryp2Chat</h1></p>
<p align="center">
	<em><code>❯ It is a communication/messaging programme over Local Network on UNIX systems using C/C++, it is an experimental project.
  Cryp2Chat is a multi-client chat application that enables secure communication over TCP/IP protocol. The project allows users to send encrypted messages to each other and perform connection management through a central server.</code></em>
</p>
<p align="center">
	<!-- Shields.io badges disabled, using skill icons. --></p>
<p align="center">Built with the tools and technologies:</p>
<p align="center">
	<a href="https://skillicons.dev">
		<img src="https://skillicons.dev/icons?i=vscode,c,cpp,md,linux&theme=dark">
	</a></p>
<br>

## 🔗 Table of Contents

- [📍 Overview](#-overview)
- [👾 Features](#-features)
- [📁 Project Structure](#-project-structure)
  - [📂 Project Index](#-project-index)
- [🚀 Getting Started](#-getting-started)
  - [☑️ Prerequisites](#-prerequisites)
  - [⚙️ Installation](#-installation)
  - [🤖 Usage](#🤖-usage)
  - [🧪 Testing](#🧪-testing)
- [📌 Project Roadmap](#-project-roadmap)
- [🔰 Contributing](#-contributing)
- [🎗 License](#-license)
- [🙌 Acknowledgments](#-acknowledgments)

---

## 📍 Overview

<code>❯ Cryp2Chat provides encrypted messaging by enabling clients to connect to the server. While user authentication and logging are performed on the server side, each transaction on the client side is recorded in a detailed log file. Messages are protected with RSA and AES encryption algorithm. (No readable data was obtained when the packets were examined over the local network)</code>

---

## 👾 Features
<code>❯- Multi-client support (up to 10 clients at the same time).</code><br>
<code>❯- Secure messaging with RSA and AES encryption.</code><br>
<code>❯- Detailed logging on server and client side.</code><br>
<code>❯- User authentication (predefined username and password).</code><br>
<code>❯- Efficient connection management with multithreading.</code><br>

---

## 📁 Project Structure

```sh
└── Cryp2Chat/
    ├── LICENSE
    ├── Makefile
    ├── README.md
    ├── client_log.log
    ├── headers
    │   ├── colorcodes.h
    │   ├── cryp2.h
    │   ├── cryptology.h
    │   ├── database.h
    │   ├── logmacro.h
    │   ├── md5apic.h
    │   ├── socketutil.h
    │   ├── strtohex.h
    │   ├── tcpclient.h
    │   └── tcpserver.h
    ├── server-key
    │   ├── private_key.pem
    │   ├── public_key.pem
    │   └── rsakeygen_openssl.txt
    └── src
        ├── TCPClient.c
        ├── TCPServer.c
        ├── cryp2.cpp
        ├── database.c
        ├── lock3r.cpp
        ├── md5apic.c
        ├── socketutil.c
        └── strtohex.c
```


### 📂 Project Index
<details closed>
	<summary><b><code>Cryp2Chat/</code></b></summary>
	<details>
		<summary><b>Makefile</b></summary>
		<blockquote>
			<table>
			<tr>
				<td><b>Makefile</b></td>
				<td>The instruction file used to compile the project.</td>
			</tr>
			</table>
		</blockquote>
	</details>
	<details>
		<summary><b>src</b></summary>
		<blockquote>
			<table>
			<tr>
				<td><b>TCPClient.c</b></td>
				<td>Contains functions necessary for the client side.</td>
			</tr>
			<tr>
				<td><b>TCPServer.c</b></td>
				<td>Contains functions necessary for the server side.</td>
			</tr>
			<tr>
				<td><b>cryp2.cpp</b></td>
				<td>Includes code related to encryption functions.</td>
			</tr>
			<tr>
				<td><b>database.c</b></td>
				<td>Handles user authentication and database functions.</td>
			</tr>
			<tr>
				<td><b>strtohex.c</b></td>
				<td>Handles the conversion of strings to hexadecimal format and back.</td>
			</tr>
			<tr>
				<td><b>lock3r.cpp</b></td>
				<td>Includes code related to encryption or connection management.</td>
			</tr>
			<tr>
				<td><b>md5apic.c</b></td>
				<td>Implements MD5-based hashing functions.</td>
			</tr>
			<tr>
				<td><b>socketutil.c</b></td>
				<td>Manages socket operations and utility functions.</td>
			</tr>
			</table>
		</blockquote>
	</details>
	<details>
		<summary><b>server-key</b></summary>
		<blockquote>
			<table>
			<tr>
				<td><b>rsakeygen_openssl.txt</b></td>
				<td>Commands for generating RSA keys.</td>
			</tr>
			</table>
		</blockquote>
	</details>
	<details>
		<summary><b>headers</b></summary>
		<blockquote>
			<table>
			<tr>
				<td><b>logmacro.h</b></td>
				<td>Macro definitions for logging operations.</td>
			</tr>
			<tr>
				<td><b>cryp2.h</b></td>
				<td>Header file for encryption-related functions.</td>
			</tr>
			<tr>
				<td><b>md5apic.h</b></td>
				<td>Header file for MD5 operations.</td>
			</tr>
			<tr>
				<td><b>strtohex.h</b></td>
				<td>Header file for string and hex conversions.</td>
			</tr>
			<tr>
				<td><b>socketutil.h</b></td>
				<td>Header file for socket operations.</td>
			</tr>
			<tr>
				<td><b>database.h</b></td>
				<td>Header file for database functions.</td>
			</tr>
			<tr>
				<td><b>cryptology.h</b></td>
				<td>Header file for cryptographic operations.</td>
			</tr>
			<tr>
				<td><b>tcpclient.h</b></td>
				<td>Header file for the client side.</td>
			</tr>
			<tr>
				<td><b>tcpserver.h</b></td>
				<td>Header file for the server side.</td>
			</tr>
			<tr>
				<td><b>colorcodes.h</b></td>
				<td>Defines color codes for terminal output.</td>
			</tr>
			</table>
		</blockquote>
	</details>
</details> 

---
## 🚀 Getting Started

### ☑️ Prerequisites

Before getting started with Cryp2Chat, ensure your runtime environment meets the following requirements:

- **C Compiler:** GCC or Clang is recommended.
- **OpenSSL Library:** Required for RSA and AES encryption.
- **Linux Operating System:** The project was tested on Ubuntu.


### ⚙️ Installation

Install Cryp2Chat using one of the following methods:

**Build from source:**

1. Clone the Cryp2Chat repository:
```sh
❯ git clone https://github.com/n0connect/Cryp2Chat
```

2. Navigate to the project directory:
```sh
❯ cd Cryp2Chat
```

3. Build Program:
```sh
❯ make build
```

4. Compile Server:
```sh
❯ make server
```

5. Compile Client:
```sh
❯ make client
```

**Clean compiled program:**
```sh
❯ make clean
```
**Generation of RSA keys:**
```sh
openssl genrsa -out server-key/private_key.pem 2048
openssl rsa -in server-key/private_key.pem -outform PEM -pubout -out server-key/public_key.pem
```

### 🤖 Usage
Start server with terminal:
```sh
❯ ./server
```
Start client with terminal:
```sh
❯ ./client
```
Log in: User names and passwords are predefined(database.c):
```sh
❯ Username : n0n0
❯ Password : n0n0
```

### 🧪 Testing
To test RSA encryption and connectivity, examine the client_log.log file. This file holds transaction details for each client.

---
## 📌 Project Roadmap

- [X] **`Task 1`**: <strike>Multi-client connection support.</strike>
- [X] **`Task 2`**: <strike>User authentication system.</strike>
- [x] **`Task 3`**: <strike>RSA and AES encryption integration.</strike>
- [ ] **`Task 4`**: GUI based client application.
- [ ] **`Task 5`**: Wider user database support.
- [ ] **`Task 6`**: Cross platform support.
- [ ] **`Task 7`**: Enhanced unique Client-Server communication reliability, Discrete algorithms, Degradable fragments or files in case of access breach, support for high-level security and true end-to-end encryption.

---

## 🔰 Contributing
The project is open source and open for contributions. You can contribute by following the steps below:
- **💬 [Join the Discussions](https://github.com/n0connect/Cryp2Chat/discussions)**
- **🐛 [Report Issues](https://github.com/n0connect/Cryp2Chat/issues)**
- **💡 [Submit Pull Requests](https://github.com/n0connect/Cryp2Chat/blob/main/CONTRIBUTING.md)**

<details closed>
<summary>Contributing Guidelines</summary>

1. **Fork the Repository**: Start by forking the project repository to your github account.
2. **Clone Locally**: Clone the forked repository to your local machine using a git client.
   ```sh
   git clone https://github.com/n0connect/Cryp2Chat
   ```
3. **Create a New Branch**: Always work on a new branch, giving it a descriptive name.
   ```sh
   git checkout -b new-feature-x
   ```
4. **Make Your Changes**: Develop and test your changes locally.
5. **Commit Your Changes**: Commit with a clear message describing your updates.
   ```sh
   git commit -m 'Implemented new feature x.'
   ```
6. **Push to github**: Push the changes to your forked repository.
   ```sh
   git push origin new-feature-x
   ```
7. **Submit a Pull Request**: Create a PR against the original project repository. Clearly describe the changes and their motivations.
8. **Review**: Once your PR is reviewed and approved, it will be merged into the main branch. Congratulations on your contribution!
</details>

<details closed>
<summary>Contributor Graph</summary>
<br>
<p align="left">
   <a href="https://github.com{/n0connect/Cryp2Chat/}graphs/contributors">
      <img src="https://contrib.rocks/image?repo=n0connect/Cryp2Chat">
   </a>
</p>
</details>

---

## 🎗 License

This project is protected under the MIT licence. See the LICENSE file for more information.

---

## 🙌 Acknowledgments

- OpenSSL for RSA and AES encryption.

---
