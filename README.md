# 🛡️ ClearSight

ClearSight is an advanced email phishing detection system built with a polyglot microservice architecture. It moves beyond passive scanning by using NLP to detect manipulative language and an active sandbox to safely investigate unknown links.

---

## ✨ Features

* **Email Analysis Engine:** Upload `.eml` files or paste email content for a full analysis.
* **Asynchronous Processing:** Uses **Celery** and **Redis** to run all analysis in the background, so the UI never freezes on large tasks.
* **Multi-Layer Heuristics:** Analyzes email headers for **SPF/DKIM** failures, content for suspicious keywords, and attachments for dangerous file types.
* **External Threat Intelligence:** Integrates with the **VirusTotal API** to check links, domains, and IPs against over 70 global security vendors.
* **NLP Sentiment Analysis:** The system uses **TextBlob** to analyze the email's sentiment, scoring its **subjectivity** to detect manipulative language that keywords might miss.
* **Active Link Sandboxing:** Our team's core contribution. A dedicated **Node.js microservice** uses **Puppeteer** (headless Chrome) to safely "click" unknown links in a secure, isolated container and return visual screenshots of the destination.
* **Historical Dashboard:** A **React** frontend to track and review all past analysis results, complete with charts and filtering.
* **Data Export:** Export analysis history in JSON or CSV format.

---

## 🚀 Quick Start

### Prerequisites
* [Git](https://git-scm.com/downloads)
* [Docker Desktop](https://www.docker.com/products/docker-desktop/)

### Running the Project
1.  **Clone the repository:**
    ```bash
    git clone [Your GitHub Repository URL]
    cd clearsight
    ```

2.  **Configure Environment:**
    Copy the environment template. This file is pre-configured for local Docker development.
    ```bash
    cp env.template .env
    ```
    Open the `.env` file and paste your VirusTotal API key:
    ```
    VIRUSTOTAL_API_KEY=your-64-character-key-here
    ```

3.  **Build and Run:**
    This command will build all container images and start all services. The first build may take several minutes as it installs the OS, dependencies, and headless browser.
    ```bash
    docker-compose up --build
    ```

4.  **Access the Application:**
    Open your browser and navigate to `http://localhost:5000`.

---

## 🛠️ Tech Stack

This project uses a **polyglot (multi-language) microservice architecture** to leverage the best technology for each task.

| Category | Technology | Purpose |
| :--- | :--- | :--- |
| **Orchestration** | Docker, Docker Compose | To containerize and manage all microservices for isolation and reliability. |
| **Backend API** | Python, Flask | The main REST API for handling file uploads and user requests. |
| **Task Queue** | Celery, Redis | Manages asynchronous background tasks (like analysis) so the API stays fast. |
| **Sandbox Service** | Node.js, Express | A dedicated microservice for securely running the browser. |
| **Browser Automation**| Puppeteer | A Node.js library used to control the headless Google Chrome instance for sandboxing. |
| **NLP** | TextBlob (Python) | Used for its pre-trained sentiment analysis model to score email subjectivity. |
| **Frontend** | React.js, Material-UI | For building a clean, responsive user interface and dashboard. |
| **Database** | MongoDB | A NoSQL database used to store the flexible, JSON-based analysis reports. |
| **Threat Intel** | VirusTotal API | Provides external data on known malicious domains, IPs, and files. |

---

## 🔧 Troubleshooting

If you encounter issues, the first step is always to check the logs for each service.

```bash
# See all running services
docker-compose ps

# Follow the logs for the main backend
docker logs -f clearsight_backend

# Follow the logs for the analysis worker (where analysis happens)
docker logs -f clearsight_worker

# Follow the logs for the sandbox service
docker logs -f clearsight_sandbox

# Stop all services
docker-compose down

# Nuke all data (database, uploads) and start fresh
docker-compose down -v