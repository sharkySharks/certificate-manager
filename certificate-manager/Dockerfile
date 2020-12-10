FROM golang:1.14-alpine

WORKDIR app

COPY go.mod go.sum ./
RUN go mod download

ADD postgres postgres
ADD certificate-manager certificate-manager

WORKDIR certificate-manager

ENTRYPOINT go run .
