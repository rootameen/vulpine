FROM golang:1.19 AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

ARG VERSION

RUN go build -o bin/vulpine -v -ldflags="-X main.version=$VERSION" 

FROM gcr.io/distroless/base-debian10

COPY --from=builder /app/bin /bin/

ENTRYPOINT ["/bin/vulpine"]
