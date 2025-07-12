# Используем официальный образ Python
FROM python:3.9-slim

# Устанавливаем зависимости системы
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Создаем и переходим в рабочую директорию
WORKDIR /app

# Копируем зависимости и устанавливаем их
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем остальные файлы
COPY . .

# Создаем папку для загрузок
RUN mkdir -p /app/uploads && \
    chmod 777 /app/uploads

# Открываем порт
EXPOSE 5000

# Запускаем приложение
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "2", "app:app"]
