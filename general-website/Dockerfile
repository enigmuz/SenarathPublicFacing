# Senarath Bank - General Website (DMZ1 Web Server 1)
# SIMULATION / SECURITY TRAINING LAB - intentionally vulnerable.
FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/logs /app/uploads

EXPOSE 8080

# Run with Flask's dev server (debug on) so stack traces are exposed - this is
# deliberate for the lab. Do NOT use this configuration for anything real.
CMD ["python", "app.py"]
