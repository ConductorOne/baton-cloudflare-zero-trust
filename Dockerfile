FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-cloudflare-zero-trust"]
COPY baton-cloudflare-zero-trust /