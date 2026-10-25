FROM alpine:3 AS fetch
ADD --checksum=sha256:9a77c0cc1726cb7a3bc4cd644561e0cfa2d9223933aa8d84f7b63abb2dba297b \
    https://git.deuxfleurs.fr/Deuxfleurs/garage-webadmin/releases/download/v0.1.0/garage-webadmin-prelease-2026-09-09_13-12.zip \
    /webadmin.zip
RUN unzip /webadmin.zip -d /

FROM caddy:2-alpine
COPY --from=fetch /garage-webadmin-prelease-2026-09-09_13-12/dist/ /srv/
COPY Caddyfile /etc/caddy/Caddyfile
