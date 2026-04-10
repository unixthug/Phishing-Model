FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip findutils libgomp1 \
 && rm -rf /var/lib/apt/lists/*
  
RUN pip install --no-cache-dir -U pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=8080
EXPOSE 8080

RUN chmod +x start.sh

CMD ["./start.sh"]