FROM golang:1.8 as buildstage
RUN mkdir -p /go/src/github.com/prometheus/blackbox_exporter
COPY . /go/src/github.com/prometheus/blackbox_exporter
ENV GOPATH=/go
RUN make -C /go/src/github.com/prometheus/blackbox_exporter build


FROM        quay.io/prometheus/busybox:latest
MAINTAINER  The Prometheus Authors <prometheus-developers@googlegroups.com>

COPY --from=buildstage /go/src/github.com/prometheus/blackbox_exporter/blackbox_exporter /bin/blackbox_exporter
COPY blackbox.yml       /etc/blackbox_exporter/config.yml

EXPOSE      9115
ENTRYPOINT  [ "/bin/blackbox_exporter" ]
CMD         [ "--config.file=/etc/blackbox_exporter/config.yml" ]
