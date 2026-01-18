FROM denoland/deno:alpine AS builder
WORKDIR /app
COPY . ./
RUN deno task build

FROM nginx:1.29-alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
