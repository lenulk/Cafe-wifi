"""
admin/routes.py — ตัวเก็บ route ของแต่ละไฟล์ใน admin/views/ แล้วค่อยผูกเข้ากับ Flask app ทีหลัง

ทำไมไม่ใช้ Flask Blueprint: Blueprint เติมชื่อหน้า endpoint ("logs.search_logs") ต้องแก้ url_for ทุกจุดใน
template และโค้ด -- แบบนี้ endpoint ยังเป็นชื่อฟังก์ชันเดิมทุกตัว แต่โค้ดแยกไฟล์ตามหน้าที่ได้
register() ถูกเรียกทุกครั้งที่ admin/app.py ทำงาน (รวมตอนเทสต์ importlib.reload) จึงผูกกับ app ตัวใหม่เสมอ
"""
from __future__ import annotations


class Routes:
    def __init__(self) -> None:
        self._items: list[tuple[str, dict, object]] = []

    def route(self, rule: str, **options):
        def deco(view):
            self._items.append((rule, options, view))
            return view
        return deco

    def get(self, rule: str, **options):
        return self.route(rule, methods=["GET"], **options)

    def post(self, rule: str, **options):
        return self.route(rule, methods=["POST"], **options)

    def register(self, app) -> None:
        for rule, options, view in self._items:
            app.add_url_rule(rule, view.__name__, view, **options)
