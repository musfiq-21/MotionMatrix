"""
Role-based permission system.

Defines permissions for each role and provides helper functions
for authorization checks.
"""

from enum import Enum
from typing import List


class RoleName(str, Enum):
    SYSTEM_ADMIN = "ADMIN"
    OWNER = "OWNER"
    MANAGER = "MANAGER"
    FLOOR_MANAGER = "FLOOR_MANAGER"
    WORKER = "WORKER"


class Permission(str, Enum):
    # User management
    CREATE_USER = "create_user"
    UPDATE_USER = "update_user"
    DELETE_USER = "delete_user"
    VIEW_ALL_USERS = "view_all_users"

    # Attendance
    MANAGE_ATTENDANCE = "manage_attendance"
    VIEW_ATTENDANCE = "view_attendance"

    # Production
    MANAGE_PRODUCTION = "manage_production"
    VIEW_PRODUCTION = "view_production"

    # Leave
    MANAGE_LEAVE = "manage_leave"
    REQUEST_LEAVE = "request_leave"

    # Reports
    VIEW_REPORTS = "view_reports"
    GENERATE_REPORTS = "generate_reports"

    # Messaging
    SEND_MESSAGE = "send_message"

    # Infrastructure
    MANAGE_FLOORS = "manage_floors"
    MANAGE_WORKSTATIONS = "manage_workstations"
    MANAGE_CAMERAS = "manage_cameras"
    MANAGE_SHIFTS = "manage_shifts"


ROLE_PERMISSIONS = {
    RoleName.SYSTEM_ADMIN: [perm for perm in Permission],
    RoleName.OWNER: [
        Permission.VIEW_ALL_USERS,
        Permission.VIEW_ATTENDANCE,
        Permission.VIEW_PRODUCTION,
        Permission.VIEW_REPORTS,
        Permission.GENERATE_REPORTS,
        Permission.SEND_MESSAGE,
    ],
    RoleName.MANAGER: [
        Permission.VIEW_ALL_USERS,
        Permission.MANAGE_ATTENDANCE,
        Permission.VIEW_ATTENDANCE,
        Permission.MANAGE_PRODUCTION,
        Permission.VIEW_PRODUCTION,
        Permission.MANAGE_LEAVE,
        Permission.VIEW_REPORTS,
        Permission.GENERATE_REPORTS,
        Permission.SEND_MESSAGE,
        Permission.MANAGE_FLOORS,
        Permission.MANAGE_SHIFTS,
    ],
    RoleName.FLOOR_MANAGER: [
        Permission.MANAGE_ATTENDANCE,
        Permission.VIEW_ATTENDANCE,
        Permission.MANAGE_PRODUCTION,
        Permission.VIEW_PRODUCTION,
        Permission.MANAGE_LEAVE,
        Permission.SEND_MESSAGE,
    ],
    RoleName.WORKER: [
        Permission.VIEW_ATTENDANCE,
        Permission.VIEW_PRODUCTION,
        Permission.REQUEST_LEAVE,
        Permission.SEND_MESSAGE,
    ],
}


def has_permission(user_role: str, required_permission: Permission) -> bool:
    """Check if a role has a specific permission."""
    try:
        role = RoleName(user_role)
    except ValueError:
        return False
    return required_permission in ROLE_PERMISSIONS.get(role, [])


def get_permissions_for_role(user_role: str) -> List[Permission]:
    """Get all permissions for a given role."""
    try:
        role = RoleName(user_role)
    except ValueError:
        return []
    return ROLE_PERMISSIONS.get(role, [])
