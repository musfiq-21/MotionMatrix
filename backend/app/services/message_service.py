"""
Message service layer.

Business logic for in-app messaging between users.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from backend.app.models.message import Message
from backend.app.schemas.message import MessageCreate


class MessageService:
    def __init__(self, db: Session):
        self.db = db

    def send_message(self, data: MessageCreate, sender_id: UUID) -> Message:
        message = Message(
            sender_id=sender_id,
            receiver_id=data.receiver_id,
            subject=data.subject,
            body=data.body,
        )
        self.db.add(message)
        self.db.commit()
        self.db.refresh(message)
        return message

    def get_inbox(self, user_id: UUID) -> List[Message]:
        return (
            self.db.query(Message)
            .filter(Message.receiver_id == user_id)
            .order_by(Message.created_at.desc())
            .all()
        )

    def get_sent_messages(self, user_id: UUID) -> List[Message]:
        return (
            self.db.query(Message)
            .filter(Message.sender_id == user_id)
            .order_by(Message.created_at.desc())
            .all()
        )

    def mark_as_read(self, message_id: UUID) -> Optional[Message]:
        from datetime import datetime
        message = self.db.query(Message).filter(Message.id == message_id).first()
        if not message:
            return None
        message.is_read = True
        message.read_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(message)
        return message
