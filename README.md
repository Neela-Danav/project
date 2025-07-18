🔐 SASTf – Static Application Security Testing for Android APKs

Welcome to SASTf, a Static Application Security Testing (SAST) framework tailored for Android APKs! This tool helps you scan APKs for potential vulnerabilities with just a few simple steps. 🛡️📱
🚀 Getting Started
🧰 Prerequisites

Before running the project, make sure you have:

    🐳 Docker

    🧩 Docker Compose

If you’re using Ubuntu, follow the official Docker installation guide:
👉 Install Docker on Ubuntu
🛠️ Install Docker on Ubuntu

    Remove any existing/conflicting Docker packages:

for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
sudo apt-get remove $pkg;
done

    Add Docker's official GPG key:

sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

    Add Docker repository to Apt sources:

echo \
 "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
 $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
 sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update

    Install Docker and Docker Compose:

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    Enable and start Docker:

sudo systemctl enable docker
sudo systemctl start docker

📥 Clone & Run

    Clone the repository:

git clone https://github.com/Neela-Danav/nico-project
cd nico-robin

    Build the Docker containers:

sudo docker compose build

    Start the application:

sudo docker compose up

    Access the application in your browser:
    👉 http://localhost:8443

👤 First-Time Setup

When you launch the application for the first time:

    🔐 Create admin credentials (this is a one-time setup).

    🧪 To scan an APK:

        Go to the "Projects" section.

        Click "Create New Project" (project name must have at least 5 characters).

        Click "Scan and Upload".

        Choose an APK file from the dropdown (appears after selecting the upload method).

        ⚠️ Do not set a time limit.

        Click "Scan" to start analysis.

🎉 Happy Scanning!

Start securing your Android apps today. 🕵️‍♂️📲
