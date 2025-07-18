# 🔐 SASTf – Static Application Security Testing for Android APKs

Welcome to **SASTf**, a Static Application Security Testing (SAST) framework tailored for Android APKs! This tool helps you scan APKs for potential vulnerabilities with just a few simple steps. 🛡️📱

---

## 🚀 Getting Started

### 🧰 Prerequisites

Before running the project, make sure you have:

- 🐳 **Docker**
- 🧩 **Docker Compose**

If you’re using **Ubuntu**, follow the official Docker installation guide:

👉 **Install Docker on Ubuntu**

#### If u are using ubuntu use this to install official version of docker compose written in go if the command below does not work refer this link to learn more: [https://docs.docker.com/engine/install/ubuntu/]

1. **Remove any existing/conflicting Docker packages:**

   ```bash
   for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
       sudo apt-get remove $pkg;
   done
   ```

2. **Add Docker's official GPG key:**

   ```bash
   sudo apt-get update
   sudo apt-get install ca-certificates curl
   sudo install -m 0755 -d /etc/apt/keyrings
   sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
   sudo chmod a+r /etc/apt/keyrings/docker.asc
   ```

3. **Add Docker repository to Apt sources:**

   ```bash
   echo \
   "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
   $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
   sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

   sudo apt-get update
   ```

4. **Install Docker and Docker Compose:**

   ```bash
   sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   ```

5. **Enable and start Docker:**

   ```bash
   sudo systemctl enable docker
   sudo systemctl start docker
   ```

---

## 📥 Clone & Run

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Neela-Danav/project
   cd project
   ```

2. **Build the Docker containers:**

   ```bash
   sudo docker compose build
   ```

3. **Start the application:**

   ```bash
   sudo docker compose up
   ```

4. **Access the application in your browser:**

   👉 [https://localhost:8443](https://localhost:8443)

---

## 👤 First-Time Setup

When you launch the application for the first time:

- 🔐 **Create admin credentials** (this is a one-time setup).
- 🧪 **To scan an APK:**

  1. Go to the "Projects" section.
  2. Click **"Create New Project"** (project name must have at least 5 characters).
  3. Click **"Scan and Upload"**.
  4. Choose an APK file from the dropdown (appears after selecting the upload method).
  5. ⚠️ **Do not set a time limit.**
  6. Click **"Scan"** to start analysis.

---

```

```
