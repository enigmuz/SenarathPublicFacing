# Senarath Bank - SenNet Online Banking (DMZ1 Web Server 2)
# SIMULATION / SECURITY TRAINING LAB - intentionally vulnerable.
FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/logs

EXPOSE 8080

# Flask dev server with debug on (deliberate, for the lab).
CMD ["python", "app.py"]
