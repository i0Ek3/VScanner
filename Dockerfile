# Use official Python slim image (lightweight)
FROM python:3.9-slim

# Set working directory inside container
WORKDIR /app

# Copy requirements file first (caching optimization)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy scanner code to container (modular structure)
COPY main.py .
COPY core/ ./core/
COPY scanners/ ./scanners/

# Set entrypoint to run the scanner (CLI arguments passed at runtime)
ENTRYPOINT ["python", "main.py"]

# Default help message (run with --help to see options)
CMD ["--help"]