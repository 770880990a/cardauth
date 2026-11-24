# 卡密验证系统 —— 云端部署镜像
# 用于 Render / Railway / Koyeb / 任何支持 Docker 的平台，也可在 VPS 上直接 docker run
FROM node:22-alpine

# 时区设为北京时间，日志和到期时间才对得上
ENV TZ=Asia/Shanghai
RUN apk add --no-cache tzdata && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo "Asia/Shanghai" > /etc/timezone

WORKDIR /app

# 先只拷依赖清单，利用 Docker 层缓存
COPY package.json ./
# 生产模式不装 pkg/better-sqlite3 等开发依赖，用 Node 内置 sqlite
RUN npm install --omit=dev --no-audit --no-fund || npm install --no-audit --no-fund

COPY server ./server
COPY public ./public

# 数据目录（云端需要挂载持久磁盘到这里，否则重启会丢数据）
ENV DB_PATH=/data/cardauth.db
ENV PORT=8787
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server/app.js"]
