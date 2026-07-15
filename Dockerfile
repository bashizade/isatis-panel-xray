FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    ca-certificates \
    jq \
    && rm -rf /var/lib/apt/lists/*

RUN XRAY_VERSION=$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name) \
    && echo "Downloading Xray ${XRAY_VERSION}" \
    && curl -fsSL -o /tmp/xray.zip \
    "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip" \
    && unzip -q /tmp/xray.zip -d /usr/local/bin \
    && rm -f /tmp/xray.zip \
    && chmod +x /usr/local/bin/xray \
    && xray version

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./
COPY public ./public

RUN mkdir -p /app/data

ENV NODE_ENV=production

EXPOSE 3000

CMD ["npm", "start"]