FROM scratch
ENV PATH=/bin

COPY adm /bin/

WORKDIR /

ENTRYPOINT ["/bin/adm"]