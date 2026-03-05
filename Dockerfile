# Use an official, lightweight Python image
FROM python:3.10-slim

# Install system dependencies: Java (for keytool) and apktool
RUN apt-get update && apt-get install -y \
    default-jre \
    apktool \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the requirements file and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all your Python scripts into the container
COPY . .

# Expose the port FastAPI uses
EXPOSE 8000

# Start the server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
