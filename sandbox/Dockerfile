# Use Debian-based Node image instead of Alpine for better browser support
FROM node:18-slim

# 1. Install utilities needed to download Chrome
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# 2. Install latest Google Chrome Stable and fonts
# We rely on the official Google Linux signing key and repository
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/googlechrome-linux-keyring.gpg \
    && sh -c 'echo "deb [arch=amd64 signed-by=/usr/share/keyrings/googlechrome-linux-keyring.gpg] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' \
    && apt-get update \
    && apt-get install -y google-chrome-stable fonts-ipafont-gothic fonts-wqy-zenhei fonts-thai-tlwg fonts-kacst fonts-freefont-ttf --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# 3. Tell Puppeteer to use the installed Chrome
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome-stable

WORKDIR /app

COPY package*.json ./
# Install dependencies (ignoring Puppeteer's attempt to download Chrome)
RUN npm install

COPY . .

# Create screenshots directory and handle permissions for the 'node' user
RUN mkdir -p /app/screenshots && \
    chown -R node:node /app/screenshots && \
    chown -R node:node /app

# Switch to non-root user for security
USER node

EXPOSE 3001
CMD ["node", "index.js"]