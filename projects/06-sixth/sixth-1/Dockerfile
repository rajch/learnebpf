FROM alpine:latest
LABEL maintainer="Raj Chaudhuri <raj@rajware.net>"

RUN apk update && apk add libbpf bash

WORKDIR /app
COPY sixth .

CMD ["./sixth"]
