FROM golang:1.13.1 as builder

WORKDIR $GOPATH/src/github.com/yahoo/k8s-athenz-identity

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go install ./... && \
    go test ./...

FROM alpine:latest

RUN apk --update add ca-certificates

COPY --from=builder /go/bin/athenz-sia /usr/bin/athenz-sia

ENTRYPOINT ["/usr/bin/athenz-sia"]