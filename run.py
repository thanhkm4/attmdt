from app import create_app

# [QUAN TRỌNG] Biến app phải nằm ngoài, không được nằm trong if __name__ == "__main__"
app = create_app() 

if __name__ == "__main__":
    # Phần này chỉ chạy khi bạn gõ 'python run.py', Docker không dùng dòng này
    app.run(host="0.0.0.0", port=1412, debug=True)
    