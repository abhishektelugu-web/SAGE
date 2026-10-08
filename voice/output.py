"""
voice/output.py
===============
Optional Voice Output (Text-to-Speech) module.

Supports local text-to-speech synthesis (pyttsx3 or Windows SAPI) with
graceful fallback to formatted console printing.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

logger = logging.getLogger(__name__)


class VoiceOutput:
    """
    Text-to-speech wrapper with fallback to standard console print.
    """

    def __init__(self, enable_tts: bool = False):
        self.enable_tts = enable_tts
        self._engine = None
        self._tts_lib_available = False

        if enable_tts:
            self._init_tts()

    def _init_tts(self) -> None:
        """Attempt to initialize local pyttsx3 or Windows SAPI."""
        try:
            import pyttsx3  # type: ignore
            self._engine = pyttsx3.init()
            self._tts_lib_available = True
        except Exception:
            # Check if Windows PowerShell SAPI is usable
            if sys.platform == "win32":
                self._tts_lib_available = True
            else:
                self._tts_lib_available = False

    def is_available(self) -> bool:
        """Returns True if TTS is enabled and engine is ready."""
        return self._tts_lib_available and self.enable_tts

    def speak(self, text: str) -> None:
        """
        Synthesize speech if TTS is enabled; otherwise formats for console.
        """
        clean_text = text.strip()
        if not clean_text:
            return

        if self.is_available():
            # 1. Try pyttsx3 engine
            if self._engine:
                try:
                    self._engine.say(clean_text)
                    self._engine.runAndWait()
                    return
                except Exception as e:
                    logger.debug("pyttsx3 speech failed: %s", e)

            # 2. Try Windows SAPI via powershell on Windows
            if sys.platform == "win32":
                try:
                    # Sanitize single quotes for PowerShell
                    safe_msg = clean_text.replace("'", " ").replace('"', " ")[:200]
                    cmd = [
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        f"Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('{safe_msg}')",
                    ]
                    subprocess.run(cmd, capture_output=True, timeout=5)
                    return
                except Exception as e:
                    logger.debug("Windows SAPI speech failed: %s", e)

        # Fallback output
        # (Silent for tests or when TTS not requested; output handled by display layers)


# Default helper instance
_default_voice_output = VoiceOutput(enable_tts=False)


def speak(text: str) -> None:
    _default_voice_output.speak(text)
