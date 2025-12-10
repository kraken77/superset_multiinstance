FROM python:3.12-slim

WORKDIR /app

# Instalace systémových závislostí
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Nastavení cesty pro spustitelné soubory nainstalované pipem
ENV PATH="/root/.local/bin:${PATH}"

# Kopírování a instalace Python závislostí
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Instalace Playwright závislostí a prohlížeče během buildu
RUN playwright install firefox --with-deps

# Kopírování všech potřebných souborů aplikace
COPY . .

# Vystavení portu
EXPOSE 8900

# Spuštění aplikace
CMD ["python", "main_docker.py"]