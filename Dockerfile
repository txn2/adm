FROM scratch
ENV PATH=/bin

COPY op /bin/

WORKDIR /

ENTRYPOINT ["/bin/op"]