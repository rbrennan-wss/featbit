# FROM bitnami/nginx:latest
# FROM bitnami/nginx:1.23.2
FROM nginx:1.23.2-alpine

USER root
# ADD ./modules/oauth-agent/certs/featbit-ca-private-cert.pem /usr/local/share/ca-certificates/featbit-ca-private-cert.pem
# ADD ./modules/oauth-agent/certs/featbit-example-wildcard.pem /usr/local/share/ca-certificates/featbit-example-wildcard.pem
# RUN chmod 644 /usr/local/share/ca-certificates/featbit-ca-private-cert.pem && update-ca-certificates
# RUN chmod 644 /usr/local/share/ca-certificates/featbit-example-wildcard.pem && update-ca-certificates

# RUN apt-get update && apt-get install -y curl dnsutils && rm -rf /var/lib/apt/lists/*

ADD ./modules/oauth-agent/certs/step-ca/root_ca.crt /usr/local/share/ca-certificates/root_ca.crt
# RUN chmod 644 /usr/local/share/ca-certificates/root_ca.crt && update-ca-certificates
RUN chmod 644 /usr/local/share/ca-certificates/root_ca.crt
RUN cat /usr/local/share/ca-certificates/root_ca.crt >> /etc/ssl/certs/ca-certificates.crt

ADD ./modules/oauth-agent/certs/step-ca/intermediate_ca.crt /usr/local/share/ca-certificates/intermediate_ca.crt
# RUN chmod 644 /usr/local/share/ca-certificates/intermediate_ca.crt && update-ca-certificates
RUN chmod 644 /usr/local/share/ca-certificates/intermediate_ca.crt
RUN cat /usr/local/share/ca-certificates/intermediate_ca.crt >> /etc/ssl/certs/ca-certificates.crt

ADD ./modules/oauth-agent/certs/step-ca/featbit-example.crt /usr/local/share/ca-certificates/featbit-example.crt
# RUN chmod 644 /usr/local/share/ca-certificates/featbit-example.crt && update-ca-certificates
RUN chmod 644 /usr/local/share/ca-certificates/featbit-example.crt
RUN cat /usr/local/share/ca-certificates/featbit-example.crt >> /etc/ssl/certs/ca-certificates.crt

# ADD ./infra/nginx/debian.bullseye.ngx_curity_http_oauth_proxy_module_1.23.2.so /usr/lib/nginx/modules/debian.bullseye.ngx_curity_http_oauth_proxy_module_1.23.2.so

# COPY C:\\Users\\rbrennan\\source\\public-forks\\featbit\\infra\\nginx\\debian.bullseye.ngx_curity_http_oauth_proxy_module_1.23.2.so /usr/lib/nginx/modules/debian.bullseye.ngx_curity_http_oauth_proxy_module_1.23.2.so
