import pytest

from redbreach.modules.base import ModuleBase


class FakeModule(ModuleBase):
    name = "fake"
    tools_required = ["echo"]

    async def recon(self, engagement, assets):
        return [{"type": "domain", "value": "found.example.com"}]

    async def enumerate(self, engagement, assets):
        return assets

    async def scan(self, engagement, assets):
        return [{"title": "Test finding", "severity": "info"}]

    async def suggest_tests(self, engagement, findings):
        return []


def test_cannot_instantiate_abstract():
    """ModuleBase cannot be instantiated directly."""
    with pytest.raises(TypeError):
        ModuleBase()


def test_concrete_module_instantiates():
    """A complete concrete subclass can be instantiated."""
    mod = FakeModule()
    assert mod.name == "fake"
    assert mod.tools_required == ["echo"]


@pytest.mark.asyncio
async def test_run_tool_available():
    """Concrete module has access to run_tool."""
    mod = FakeModule()
    result = await mod.run_tool(["echo", "test"])
    assert result.returncode == 0
    assert "test" in result.stdout


@pytest.mark.asyncio
async def test_parse_output_default():
    """Default parse_output returns lines as dicts."""
    mod = FakeModule()
    result = mod.parse_output("echo", "line1\nline2\n")
    assert len(result) == 2
    assert result[0]["raw"] == "line1"
