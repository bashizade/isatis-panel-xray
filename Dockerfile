FROM node:20-slim

# نصب ابزارهای مورد نیاز برای دانلود و اکسترکت
RUN apt-get update && \
    apt-get install -y curl unzip ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# دانلود باینری Xray-core (نسخه رو در صورت نیاز آپدیت کنید)
ARG XRAY_VERSION=v1.8.24
RUN curl -fsSL -o /tmp/xray.zip \
      https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip && \
    mkdir -p /app/bin && \
    unzip -o /tmp/xray.zip -d /app/bin && \
    rm /tmp/xray.zip && \
    chmod +x /app/bin/xray && \
    rm -f /app/bin/geoip.dat /app/bin/geosite.dat 2>/dev/null || true

# نصب dependency های Node
COPY package*.json ./
RUN npm install --omit=dev

# کپی بقیه‌ی سورس
COPY . .

EXPOSE 3000

CMD ["node", "server.js"]