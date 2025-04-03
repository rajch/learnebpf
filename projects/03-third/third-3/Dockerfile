FROM alpine:latest
LABEL maintainer="Me"

RUN apk update && apk add libbpf

WORKDIR /opt/rajware/bpfmon
COPY third .

CMD ["./third"]
