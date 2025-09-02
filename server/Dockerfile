#### Etapa 1: Build da aplicação

# Usa uma imagem base leve com Node.js
FROM node:20-alpine AS builder

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Copia os arquivos de dependências (package.json e package-lock.json) e compilar o TypeScript
COPY package*.json tsconfig.json ./

# Copia o código-fonte TypeScript para dentro do container
COPY src ./src

# Instala todas as dependências, incluindo as de desenvolvimento
RUN npm install

# Compila o código TypeScript, gerando os arquivos JavaScript em /app/dist
RUN npm run build


#### Etapa 2: Execução da aplicação

#### Etapa 2: Execução da aplicação
FROM node:20-alpine AS production

# Instala o openssl
RUN apk add --no-cache openssl

WORKDIR /app

# Copia os arquivos necessários
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json ./ 
COPY --from=builder /app/node_modules ./node_modules
COPY public ./public

# Gera as pastas e chaves/certificados
RUN mkdir -p keys certs && \
    openssl genrsa -out keys/private.pem 2048 && \
    openssl rsa -in keys/private.pem -outform PEM -pubout -out keys/public.pem && \
    openssl genrsa -out certs/key.pem 2048 && \
    openssl req -new -x509 -key certs/key.pem -out certs/cert.pem -days 365 -subj "/CN=localhost"

ENV NODE_ENV=production

CMD ["node", "dist/index.js"]

