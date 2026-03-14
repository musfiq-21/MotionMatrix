"""
Import all models here so Alembic can detect them for migrations.
"""

from backend.app.models.user import User
from backend.app.models.role import Role
from backend.app.models.floor import Floor
from backend.app.models.workstation import Workstation
from backend.app.models.camera import Camera
from backend.app.models.worker import Worker
from backend.app.models.shift import Shift
from backend.app.models.attendance import Attendance
from backend.app.models.production import Production
from backend.app.models.overtime import Overtime
from backend.app.models.leave_request import LeaveRequest
from backend.app.models.idle_time import IdleTime
from backend.app.models.message import Message
from backend.app.models.notification import Notification
from backend.app.models.session import UserSession

__all__ = [
    "User",
    "Role",
    "Floor",
    "Workstation",
    "Camera",
    "Worker",
    "Shift",
    "Attendance",
    "Production",
    "Overtime",
    "LeaveRequest",
    "IdleTime",
    "Message",
    "Notification",
    "UserSession",
]