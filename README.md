🔐 SASTf for Android APKs

Welcome to SASTf – a Static Application Security Testing framework tailored for Android APKs! This tool helps you scan APKs for potential vulnerabilities with just a few simple steps. 🛡️📱

---

🚀 Getting Started

🧰 Prerequisites

Before running the project, make sure you have:

- 🐳 Docker
- 🧩 Docker Compose

---

If using ubuntu refer to [https://docs.docker.com/engine/install/ubuntu/](https://docs.docker.com/engine/install/ubuntu/)

run :

for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done

then :

# Add Docker's official GPG key:

sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:

echo \
 "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
 $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
 sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

then

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

after that :

sudo systemctl enable docker
sudo systemctl start docker

📥 Clone & Run

1. Clone the repository:
   git clone [https://github.com/Neela-Danav/project](https://github.com/Neela-Danav/nico-project)
   cd nico-robuin

2. Build the Docker containers:
   sudo docker compose build

3. Start the application:
   sudo docker compose up

4. Open your browser and go to:
   👉 http://localhost:8443

---

👤 First-Time Setup

On first launch:

1. 🔐 Create your admin credentials (this is a one-time setup).
2. 🧪 To scan an APK:
   - Go to the "Projects" section.
   - Click "Create New Project". Project name must have at least 5 characters.
   - Click "Scan and Upload".
   - Choose an APK file from the dropdown (appears after selecting upload method).
   - ⚠️ Do not set a time limit.
   - Click "Scan" to start analysis.

---

Happy scanning! 🕵️‍♂️📲

# nico-robin

# nico-robin

# project
