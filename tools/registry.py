
from typing import Callable, Dict

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, dict] = {}

    def register(
        self,
        name: str,
        description: str,
        func: Callable,
        input_schema: dict | None = None
    ):
        if name in self._tools:
            raise ValueError(f"Tool '{name}' already registered")

        self._tools[name] = {
            "description": description,
            "func": func,
            "input_schema": input_schema or {}
        }

    def get(self, name: str):
        return self._tools.get(name)

    def list_tools(self):
        return {
            name: meta["description"]
            for name, meta in self._tools.items()
        }

    def run(self, name: str, **kwargs):
        tool = self.get(name)
        if not tool:
            raise ValueError(f"Tool '{name}' not found")

        return tool["func"](**kwargs)
