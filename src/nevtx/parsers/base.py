from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from nevtx.core.models import EventRecord


class BaseEventParser(ABC):
    """Abstract base class for all .evtx parsers."""

    @abstractmethod
    def parse(self, file_path: Path) -> Iterator[EventRecord]:
        """Stream event records from an .evtx file.
        
        Args:
            file_path: Path to the .evtx file.

        Yields:
            EventRecord objects.
        """
        pass
