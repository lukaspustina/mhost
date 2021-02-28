# Builder Image
# hadolint ignore=DL3007
FROM alpine:latest as builder
ARG RELEASE_TAG
# hadolint ignore=DL3018
RUN apk --no-cache add curl
RUN mkdir /build
RUN echo curl --silent -L https://github.com/lukaspustina/mhost/releases/download/${RELEASE_TAG}/mhost-linux-musl-x86_64 -o /build/mhost
RUN curl --silent -L https://github.com/lukaspustina/mhost/releases/download/${RELEASE_TAG}/mhost-linux-musl-x86_64 -o /build/mhost
RUN chmod +x /build/mhost

# Final Image
# hadolint ignore=DL3007
FROM alpine:latest
COPY --from=builder /build/mhost /usr/local/bin/mhost
CMD ["echo", "USAGE: docker run -ti mhost:<image tag> mhost <arguments and options>, e.g., docker run -ti mhost:latest mhost l mhost.pustina.de"]
