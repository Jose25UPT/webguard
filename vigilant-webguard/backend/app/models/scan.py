from pydantic import BaseModel
from typing import Optional

class ScanResult(BaseModel):
    scan_id: str
    target: str
    tool: str
    status: str
    output_file: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    returncode: Optional[int] = None
