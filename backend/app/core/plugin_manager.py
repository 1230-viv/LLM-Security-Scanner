from __future__ import annotations

from app.detectors.base import DetectorPlugin
from app.detectors.data_leakage import DataLeakageDetector
from app.detectors.jailbreak import JailbreakDetector
from app.detectors.prompt_injection import PromptInjectionDetector


class PluginManager:
    """Registers and resolves detector plugins."""

    def __init__(self) -> None:
        self._detectors: list[DetectorPlugin] = []
        self.register_detector(PromptInjectionDetector())
        self.register_detector(JailbreakDetector())
        self.register_detector(DataLeakageDetector())

    def register_detector(self, detector: DetectorPlugin) -> None:
        self._detectors.append(detector)

    def get_detectors(self, categories: list[str]) -> list[DetectorPlugin]:
        category_set = set(categories)
        selected = [
            detector
            for detector in self._detectors
            if detector.supported_categories.intersection(category_set)
        ]
        return selected or self._detectors.copy()

    @property
    def detectors(self) -> list[DetectorPlugin]:
        return self._detectors.copy()
