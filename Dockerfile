FROM python:3.11-slim

LABEL maintainer="Shield Agents Contributors"
LABEL description="AI-Powered Multi-Agent Cybersecurity Scanner"
LABEL version="2.0.0"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy package
COPY . .

# Install the package
RUN pip install --no-cache-dir -e .

# Create reports directory
RUN mkdir -p /app/shield-reports

# Default command
ENTRYPOINT ["shield-agents"]
CMD ["scan", "--help"]
