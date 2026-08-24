FROM golang:1.23 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/halden-identity ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/halden-identity /usr/local/bin/halden-identity

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/halden-identity"]
