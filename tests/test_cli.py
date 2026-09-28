from __future__ import annotations

import os

from cc_trace_kb.cli import (
    _choose_interactive_provider,
    _resolve_api_key,
    _resolve_llm_setup,
)
from cc_trace_kb.semantic_mapper import build_semantic_client


class Feeder:
    def __init__(self, answers):
        self.answers=iter(answers)
    def __call__(self, prompt=""):
        return next(self.answers)


def test_interactive_provider_defaults_to_none():
    out=[]
    provider=_choose_interactive_provider(input_fn=Feeder([""]),output_fn=out.append)
    assert provider=="none"
    assert any("Gemini" in line for line in out)


def test_interactive_provider_accepts_gemini_number():
    provider=_choose_interactive_provider(input_fn=Feeder(["1"]),output_fn=lambda _:None)
    assert provider=="gemini"


def test_api_key_uses_environment_without_prompt(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY","env-secret")
    called=False
    def secret_input(prompt=""):
        nonlocal called
        called=True
        raise AssertionError("secret prompt should not run")
    assert _resolve_api_key("gemini",secret_input_fn=secret_input,output_fn=lambda _:None)=="env-secret"
    assert called is False


def test_api_key_is_prompted_hidden_and_not_printed(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY",raising=False)
    out=[]
    prompts=[]
    def secret_input(prompt=""):
        prompts.append(prompt)
        return "super-secret"
    key=_resolve_api_key("gemini",secret_input_fn=secret_input,output_fn=out.append)
    assert key=="super-secret"
    assert prompts and "Gemini API Key" in prompts[0]
    assert all("super-secret" not in line for line in out)


def test_resolve_llm_setup_prompts_provider_and_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY",raising=False)
    provider,key=_resolve_llm_setup(
        None,
        prompt_provider=True,
        input_fn=Feeder(["1"]),
        secret_input_fn=Feeder(["k-test"]),
        output_fn=lambda _:None,
    )
    assert provider=="gemini"
    assert key=="k-test"


def test_explicit_none_never_prompts_for_key():
    provider,key=_resolve_llm_setup(
        "none",
        prompt_provider=False,
        secret_input_fn=lambda _: (_ for _ in ()).throw(AssertionError("must not prompt")),
        output_fn=lambda _:None,
    )
    assert provider=="none"
    assert key is None


def test_explicit_api_key_reaches_semantic_client(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY",raising=False)
    client=build_semantic_client("gpt",model="test-model",api_key="explicit-secret")
    assert client.provider=="openai"
    assert client.api_key=="explicit-secret"
