FROM node:18-slim

# نصب وابستگی‌ها و دانلود آخرین نسخه Xray-Core
RUN apt-get update && apt-get install -y wget unzip curl && \
    VERSION=$(curl -sL https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep tag_name | sed 's/.*"v\([^"]*\)".*/\1/') && \
    wget -O /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/v${VERSION}/Xray-linux-64.zip" && \
    unzip /tmp/xray.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/xray && \
    rm -rf /tmp/xray.zip /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 3000

CMD ["npm", "start"]