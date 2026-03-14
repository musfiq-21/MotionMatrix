"""
Notification service layer.

Business logic for creating and managing notifications.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from backend.app.models.notification import Notification
from backend.app.schemas.notification import NotificationCreate


class NotificationService:
    def __init__(self, db: Session):
        self.db = db

    def create_notification(self, data: NotificationCreate) -> Notification:
        notification = Notification(
            user_id=data.user_id,
            notification_type=data.notification_type,
            title=data.title,
            body=data.body,
        )
        self.db.add(notification)
        self.db.commit()
        self.db.refresh(notification)
        return notification

    def get_notifications_for_user(self, user_id: UUID, unread_only: bool = False) -> List[Notification]:
        query = self.db.query(Notification).filter(Notification.user_id == user_id)
        if unread_only:
            query = query.filter(Notification.is_read == False)
        return query.order_by(Notification.created_at.desc()).all()

    def mark_as_read(self, notification_id: UUID) -> Optional[Notification]:
        from datetime import datetime
        notification = self.db.query(Notification).filter(Notification.id == notification_id).first()
        if not notification:
            return None
        notification.is_read = True
        notification.read_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(notification)
        return notification

    def mark_all_as_read(self, user_id: UUID) -> int:
        from datetime import datetime
        count = (
            self.db.query(Notification)
            .filter(Notification.user_id == user_id, Notification.is_read == False)
            .update({"is_read": True, "read_at": datetime.utcnow()})
        )
        self.db.commit()
        return count
