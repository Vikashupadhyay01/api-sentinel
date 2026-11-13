"""
Week 2 (Member 2): Integration & Testing - Parser Module
Rebuild HTTP request/response pairs from captured traffic.
Parses raw bytes into structured Request/Response records.
"""

from typing import Dict, Any, Optional, Tuple

class HTTPRecord:
    def __init__(self, raw_bytes: bytes):
        self.raw_bytes = raw_bytes
        self.method: Optional[str] = None
        self.path: Optional[str] = None
        self.headers: Dict[str, str] = {}
        self.body: Optional[bytes] = None
        self.status_code: Optional[int] = None
        self.is_request = True
        self._parse()

    def _parse(self) -> None:
        if not self.raw_bytes:
            return

        try:
            # Split headers and body by double newline (supporting both CRLF and LF)
            if b"\r\n\r\n" in self.raw_bytes:
                header_bytes, self.body = self.raw_bytes.split(b"\r\n\r\n", 1)
            elif b"\n\n" in self.raw_bytes:
                header_bytes, self.body = self.raw_bytes.split(b"\n\n", 1)
            else:
                header_bytes = self.raw_bytes
                self.body = b""

            # Decode lines safely
            header_lines = header_bytes.decode(errors="ignore").splitlines()
            if not header_lines:
                return

            # Parse start line
            start_line = header_lines[0].strip()
            parts = start_line.split(" ")

            # Determine whether it's an HTTP Request or Response
            if start_line.startswith("HTTP/"):
                self.is_request = False
                if len(parts) >= 2:
                    try:
                        self.status_code = int(parts[1])
                    except ValueError:
                        self.status_code = 0
            else:
                self.is_request = True
                if len(parts) >= 2:
                    self.method = parts[0]
                    self.path = parts[1]

            # Parse HTTP Headers
            for line in header_lines[1:]:
                if ":" in line:
                    key, val = line.split(":", 1)
                    self.headers[key.strip().lower()] = val.strip()

        except Exception as e:
            print(f"Error parsing raw bytes into HTTP record: {e}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_request": self.is_request,
            "method": self.method,
            "path": self.path,
            "status_code": self.status_code,
            "headers": self.headers,
            "body_length": len(self.body) if self.body else 0
        }


def parse_raw_traffic(raw_bytes: bytes) -> HTTPRecord:
    """
    Parses incoming raw byte stream from the eBPF/Rust sniffer 
    into a structured HTTP record for backend threat monitoring.
    """
    return HTTPRecord(raw_bytes)