FROM python:3.13-slim

WORKDIR /app

# Install system dependencies if needed (uncomment if you need build tools)
# RUN apt-get update && apt-get install -y build-essential

# Copy only requirements first for caching (if you have requirements.txt)
# COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt

# Copy the whole project
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "mcp-cyberbro-server.py"]