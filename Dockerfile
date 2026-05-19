FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1000 appuser && chown -R appuser /app
USER appuser

EXPOSE 5000

ENTRYPOINT ["python3", "main.py"]
CMD ["--all"]