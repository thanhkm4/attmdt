MENU = [
    {
        "key": "config",
        "label": "Quản lý cấu hình",
        "icon": "bi-gear-fill",
        "roles": ["admin", "unit_manager", "station_manager"],
        "children": [
            {"label": "Kết nối & Dữ liệu", "endpoint": None, "icon": "bi-hdd-network", "enabled": False},
            {"label": "Quản lý người dùng", "endpoint": None, "icon": "bi-people-fill", "enabled": True},
            {"label": "Quản lý trạm", "endpoint": None, "icon": "bi-hdd-rack", "enabled": True},
            {"label": "Quản lý cảm biến trạm", "endpoint": None, "icon": "bi-sliders", "enabled": True},
        ]
        
    }
]