from pydantic import BaseModel
from typing import Optional

class UserRecord(BaseModel):
    userId: str
    hashedPassword: str
    publicKey: Optional[str] = ""
