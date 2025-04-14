FROM alpine:latest
LABEL maintainer="Me"

RUN apk update && apk add libbpf

WORKDIR /app
COPY third .

CMD ["./third"]
