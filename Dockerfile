# 1. Base Image: Python 3.8
FROM python:3.8-slim

# 2. Cài đặt thư viện hệ thống cần thiết (nếu psycopg2 cần build)
# libpq-dev dùng cho PostgreSQL, gcc dùng để compile

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    tzdata \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Thiết lập giờ Việt Nam (Asia/Ho_Chi_Minh)
ENV TZ=Asia/Ho_Chi_Minh
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 3. Thư mục làm việc
WORKDIR /app

# 4. Copy requirements và cài đặt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# 5. Copy toàn bộ code vào
COPY . .

# 6. Tạo thư mục logs (để tránh lỗi permission khi app khởi động)
RUN mkdir -p logs

# 7. Mở port 5000
EXPOSE 1412
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
