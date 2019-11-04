# Dockerfile based on https://github.com/chemidy/smallest-secured-golang-docker-image
# (see: https://medium.com/p/4752223b7324/responses/show)

############################
# STEP 1 build executable binary
############################
# golang alpine 1.13.4-alpine
FROM golang:1.13.4-alpine as builder

# Install git + SSL ca certificates.
# Git is required for fetching the dependencies.
# Ca-certificates is required to call HTTPS endpoints.
RUN apk update && apk add --no-cache git ca-certificates tzdata && update-ca-certificates

# Create appuser
RUN adduser -D -g '' appuser

WORKDIR /wd
COPY . /wd

# Build the binary
RUN GOOS=linux go build -ldflags="-w -s" -o /redactr -mod=vendor cmd/redactr/main.go

############################
# STEP 2 build a small image
############################
FROM scratch

# Import from builder.
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd

# Copy our static executable
COPY --from=builder /redactr /redactr

# Use an unprivileged user.
USER appuser

# Run redactr
ENTRYPOINT ["/redactr"]
