# Use the base image with Python
FROM mcr.microsoft.com/vscode/devcontainers/python:3.11

# Install docker-compose
RUN curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose && \
    chmod +x /usr/local/bin/docker-compose

# Set the working directory
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Make entrypoint.sh executable
RUN chmod +x .devcontainer/entrypoint.sh

# Specify the entrypoint script
ENTRYPOINT [".devcontainer/entrypoint.sh"]

EXPOSE 8000