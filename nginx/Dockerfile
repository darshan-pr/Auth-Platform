FROM nginx:1.27-alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy custom config
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# Create log directory
RUN mkdir -p /var/log/nginx

# Health check
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD wget -q -O /dev/null http://localhost:80/nginx-health || exit 1

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
