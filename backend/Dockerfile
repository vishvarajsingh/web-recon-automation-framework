FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./root-requirements.txt
COPY backend/requirements.txt ./backend-requirements.txt
COPY pyproject.toml ./
RUN pip install --no-cache-dir -r root-requirements.txt -r backend-requirements.txt

COPY config.py main.py ./
COPY modules ./modules
COPY reporting ./reporting
COPY backend/app ./app
RUN pip install --no-cache-dir --no-deps .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
