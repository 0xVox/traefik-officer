FROM golang:1.13-alpine AS builder
RUN mkdir /app
WORKDIR /app
ADD pkg/ ./
RUN apk add git; \
    go get "github.com/hpcloud/tail"; \
    go get "github.com/prometheus/client_golang/prometheus"; \
    go get "github.com/mitchellh/go-ps"; \
    go get "github.com/sirupsen/logrus"; \
    go build -o traefikofficer .

FROM golang:1.13-alpine

COPY --from=builder /app/traefikofficer ./

ENTRYPOINT [ "./traefikofficer" ]
