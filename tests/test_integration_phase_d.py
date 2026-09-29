import pytest

from redbreach.modules.cloud import CloudModule
from redbreach.modules.network import NetworkModule
from redbreach.modules.api import APIModule
from redbreach.modules.ai_llm import AILLMModule
from redbreach.core.tool_health import ALL_TOOLS, PHASE_D_TOOLS


def test_all_modules_have_correct_interface():
    for ModuleClass in [CloudModule, NetworkModule, APIModule, AILLMModule]:
        mod = ModuleClass()
        assert hasattr(mod, "name")
        assert hasattr(mod, "tools_required")
        assert hasattr(mod, "recon")
        assert hasattr(mod, "enumerate")
        assert hasattr(mod, "scan")
        assert hasattr(mod, "suggest_tests")
        assert hasattr(mod, "parse_output")


def test_phase_d_tools_in_all_tools():
    for tool in PHASE_D_TOOLS:
        assert tool in ALL_TOOLS


def test_module_names_unique():
    modules = [CloudModule(), NetworkModule(), APIModule(), AILLMModule()]
    names = [m.name for m in modules]
    assert len(names) == len(set(names))


def test_each_module_has_tools():
    for ModuleClass in [CloudModule, NetworkModule, APIModule, AILLMModule]:
        mod = ModuleClass()
        assert len(mod.tools_required) > 0
