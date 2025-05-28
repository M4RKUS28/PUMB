from sqlalchemy import Column, Integer, String, Text
from ..db.database import Base

class ServerSetting(Base):
    __tablename__ = "server_settings"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True, nullable=False)
    value = Column(Text, nullable=False) # Store all values as text, parse them in application logic
    description = Column(Text, nullable=True)
