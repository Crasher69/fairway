# Сборка. Версия проставляется через ldflags, символы вырезаются (-s -w):
# бинарник худеет примерно на четверть, а отладка в проде всё равно идёт
# по логам и админке, а не по gdb.
FROM golang:1.27-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/fairway ./cmd/fairway

# Финальный образ — пустой. Внутри один файл плюс два, без которых
# он бесполезен.
FROM scratch

# Корневые сертификаты обязательны. Без них в режиме MITM не проверить
# сертификат цели: соединение к любому HTTPS-сайту падает с
# «x509: certificate signed by unknown authority». Это первое, обо что
# спотыкается сборка на scratch.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Часовые пояса: без них время в логах и в панели будет только UTC.
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo

COPY --from=build /out/fairway /fairway

# Непривилегированный пользователь. Числом, а не именем: в scratch нет
# /etc/passwd, и имя разрешить некому.
USER 65534:65534

# Данные (корневой CA и рейтинги) должны переживать пересоздание контейнера.
VOLUME ["/data"]

EXPOSE 8080 8081

# Админка внутри контейнера слушает все интерфейсы: loopback контейнера
# недоступен снаружи. Наружу её пробрасывать только на 127.0.0.1 хоста:
#   docker run -p 8080:8080 -p 127.0.0.1:8081:8081 ...
ENTRYPOINT ["/fairway"]
CMD ["-proxy", ":8080", \
     "-admin", ":8081", \
     "-config", "/data/config.json", \
     "-data", "/data"]
