FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-hashicorp-vault"]
COPY baton-hashicorp-vault /