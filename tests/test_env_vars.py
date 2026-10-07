"""Pure unit tests for ``mattstash.core.env_vars`` (selection rules, name validation, rendering)."""

import json
import logging
import shutil
import subprocess
from typing import Dict, List, Optional

import pytest

from mattstash.core.env_vars import (
    collect_env,
    derive_env_name,
    format_dotenv,
    format_env,
    format_json,
    format_shell,
    parse_mapping,
    parse_mappings,
    split_target,
    validate_env_name,
)
from mattstash.utils.exceptions import CredentialNotFoundError


class DictSource:
    """``{title: {field: value}}`` as a SecretSource."""

    def __init__(self, data: Dict[str, Dict[str, Optional[str]]]) -> None:
        self.data = data

    def titles(self, prefix: str) -> List[str]:
        return [t for t in self.data if t.startswith(prefix)]

    def value(self, title: str, field: str) -> Optional[str]:
        if title not in self.data:
            raise CredentialNotFoundError(f"secret not found: {title}")
        return self.data[title].get(field)


SOURCE = DictSource(
    {
        "app/db": {"password": "pw1", "username": "dbuser", "url": "db:5432", "notes": "note", "region": "eu"},
        "app/key.v2": {"password": "pw2"},
        "other": {"password": "pw3"},
        "app/empty": {"password": ""},
    }
)


# ---------------------------------------------------------------------------
# names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["A", "_", "a1", "_1", "DB_PASSWORD", "x_Y_z9"])
def test_valid_env_names(name: str):
    assert validate_env_name(name) == name


@pytest.mark.parametrize("name", ["", "1a", "a-b", "a b", "a.b", "a=b", "é", "a\n", "a;b", "$x", "x\0", "ä"])
def test_invalid_env_names(name: str):
    with pytest.raises(ValueError, match="invalid environment variable name"):
        validate_env_name(name)


@pytest.mark.parametrize(
    "title,prefix,kwargs,expected",
    [
        ("app/db-password", "app/", {}, "db_password"),
        ("app/db-password", "app/", {"upper": True}, "DB_PASSWORD"),
        ("app/db-password", "app/", {"strip_prefix": False}, "app_db_password"),
        ("app/db-password", "app/", {"strip_prefix": False, "upper": True}, "APP_DB_PASSWORD"),
        ("a.b c/d", "", {}, "a_b_c_d"),
        ("Ünï/x", "", {}, "_n__x"),
        ("app/a", "app/", {}, "a"),
        ("PRE_X", "PRE_", {}, "X"),
    ],
)
def test_derive_env_name(title: str, prefix: str, kwargs: dict, expected: str):
    assert derive_env_name(title, prefix, **kwargs) == expected


@pytest.mark.parametrize("title,prefix", [("app/1st", "app/"), ("app/", "app/"), ("x", "x"), ("a/9", "a/")])
def test_derive_env_name_refuses_invalid_results(title: str, prefix: str):
    with pytest.raises(ValueError, match="valid environment variable name"):
        derive_env_name(title, prefix)


# ---------------------------------------------------------------------------
# mappings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("DB_PASS=app/db", ("DB_PASS", "app/db", "password")),
        ("DB_USER=app/db:username", ("DB_USER", "app/db", "username")),
        ("REGION=app/db:region", ("REGION", "app/db", "region")),
        ("X=a:b:password", ("X", "a:b", "password")),  # the field is after the LAST colon
        ("X=title=with=equals", ("X", "title=with=equals", "password")),  # only the first '=' splits
        ("X=sp ace/title:url", ("X", "sp ace/title", "url")),
    ],
)
def test_parse_mapping(spec: str, expected: tuple):
    mapping = parse_mapping(spec)
    assert (mapping.env_name, mapping.title, mapping.field) == expected


@pytest.mark.parametrize(
    "spec", ["", "NOEQUALS", "=app/db", "X=", "X=:password", "X=title:", "1X=title", "A-B=title", "X Y=t"]
)
def test_parse_mapping_rejects_garbage(spec: str):
    with pytest.raises(ValueError):
        parse_mapping(spec)


def test_split_target():
    assert split_target("a") == ("a", "password")
    assert split_target("a:notes") == ("a", "notes")
    assert split_target("a:b") == ("a", "b")


def test_parse_mappings_detects_duplicates():
    assert parse_mappings(["A=x", "B=y:url"]) == {"A": "x", "B": "y:url"}
    with pytest.raises(ValueError, match="more than once"):
        parse_mappings(["A=x", "A=y"])


# ---------------------------------------------------------------------------
# collect_env
# ---------------------------------------------------------------------------


def test_prefix_selection(caplog: pytest.LogCaptureFixture):
    with caplog.at_level(logging.WARNING):
        env = collect_env(SOURCE, prefix="app/")
    assert env == {"db": "pw1", "key_v2": "pw2"}
    assert "skipping 'app/empty'" in caplog.text
    assert "pw1" not in caplog.text


def test_prefix_options():
    assert collect_env(SOURCE, prefix="app/", upper=True) == {"DB": "pw1", "KEY_V2": "pw2"}
    assert collect_env(SOURCE, prefix="app/", strip_prefix=False) == {"app_db": "pw1", "app_key_v2": "pw2"}
    assert collect_env(SOURCE, prefix="")["other"] == "pw3"  # "" selects everything


def test_mappings_with_fields():
    env = collect_env(
        SOURCE,
        mappings={"U": "app/db:username", "P": "app/db", "H": "app/db:url", "N": "app/db:notes", "R": "app/db:region"},
    )
    assert env == {"U": "dbuser", "P": "pw1", "H": "db:5432", "N": "note", "R": "eu"}


def test_mappings_accept_iterables_and_a_single_string():
    assert collect_env(SOURCE, mappings=["A=other", "B=app/db:username"]) == {"A": "pw3", "B": "dbuser"}
    assert collect_env(SOURCE, mappings="A=other") == {"A": "pw3"}


def test_prefix_and_mappings_combine():
    env = collect_env(SOURCE, prefix="app/", mappings={"EXTRA": "other"})
    assert env == {"db": "pw1", "key_v2": "pw2", "EXTRA": "pw3"}


def test_nothing_selected_is_an_error():
    with pytest.raises(ValueError, match="nothing selected"):
        collect_env(SOURCE)
    with pytest.raises(ValueError, match="nothing selected"):
        collect_env(SOURCE, mappings={})


def test_prefix_without_match_is_not_found():
    with pytest.raises(CredentialNotFoundError, match="no secrets found with prefix 'zzz/'"):
        collect_env(SOURCE, prefix="zzz/")
    with pytest.raises(CredentialNotFoundError):  # even when mappings would match
        collect_env(SOURCE, prefix="zzz/", mappings={"A": "other"})


def test_missing_secret_or_empty_field_is_not_found():
    with pytest.raises(CredentialNotFoundError, match="not found"):
        collect_env(SOURCE, mappings={"A": "nope"})
    with pytest.raises(CredentialNotFoundError, match="no value for field 'url'"):
        collect_env(SOURCE, mappings={"A": "other:url"})
    with pytest.raises(CredentialNotFoundError, match="no value for field 'nope'"):
        collect_env(SOURCE, mappings={"A": "app/db:nope"})
    with pytest.raises(CredentialNotFoundError, match="no value"):
        collect_env(SOURCE, mappings={"A": "app/empty"})


def test_everything_empty_is_an_error():
    only_empty = DictSource({"p/x": {"password": ""}})
    with pytest.raises(CredentialNotFoundError, match="nothing to export"):
        collect_env(only_empty, prefix="p/")


def test_collision_between_derived_names_names_the_titles_not_the_values():
    source = DictSource({"p/a-b": {"password": "SECRET-ONE"}, "p/a_b": {"password": "SECRET-TWO"}})
    with pytest.raises(ValueError, match="a_b would be set by both") as excinfo:
        collect_env(source, prefix="p/")
    assert "p/a-b" in str(excinfo.value) and "p/a_b" in str(excinfo.value)
    assert "SECRET" not in str(excinfo.value)


def test_collision_with_upper_and_between_prefix_and_map():
    source = DictSource({"p/Foo": {"password": "1"}, "p/FOO": {"password": "2"}, "q": {"password": "3"}})
    assert collect_env(source, prefix="p/") == {"Foo": "1", "FOO": "2"}
    with pytest.raises(ValueError, match="FOO would be set by both"):
        collect_env(source, prefix="p/", upper=True)
    with pytest.raises(ValueError, match="Foo would be set by both"):
        collect_env(source, prefix="p/", mappings={"Foo": "q"})


def test_invalid_names_never_reach_the_output():
    with pytest.raises(ValueError, match="invalid environment variable name"):
        collect_env(SOURCE, mappings={"BAD-NAME": "other"})
    with pytest.raises(ValueError, match="valid environment variable name"):
        collect_env(DictSource({"p/9": {"password": "x"}}), prefix="p/")


def test_nul_in_a_value_is_refused():
    with pytest.raises(ValueError, match="NUL"):
        collect_env(DictSource({"p/x": {"password": "a\0b"}}), prefix="p/")


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

HOSTILE = [
    "plain",
    "with space",
    "it's",
    'say "hi"',
    "$(touch /tmp/pwned)",
    "`id`",
    "${HOME}",
    "$HOME",
    "back\\slash",
    "line1\nline2",
    "trailing newline\n",
    "tab\there",
    "semi;colon && pipe | redirect > file < in",
    "star * glob ? [a-z] ~ ! #comment",
    "-n",
    "-rf /",
    "'; export PWNED=1; echo '",
    '"; export PWNED=1; echo "',
    "ünï €😀",
    " leading and trailing ",
    "=",
    "a=b",
    "\\n literal",
    "'''",
    "$'ansi'",
]


def test_format_shell_basic():
    assert format_shell({"B": "two words", "A": "1"}) == "export A=1\nexport B='two words'\n"
    assert format_shell({}) == ""


def test_format_shell_validates_names():
    with pytest.raises(ValueError):
        format_shell({"a b": "x"})
    with pytest.raises(ValueError):
        format_shell({"A;rm -rf /;B": "x"})


@pytest.mark.parametrize("shell", [p for p in ("/bin/sh", shutil.which("bash"), shutil.which("dash")) if p])
def test_format_shell_output_is_inert_when_evaluated(shell: str, tmp_path):
    """eval the generated code: every value is reproduced byte for byte and nothing is executed."""
    env = {f"V{i}": value for i, value in enumerate(HOSTILE)}
    code = format_shell(env)
    marker = tmp_path / "pwned"
    script = (
        'eval "$1"\n'
        + "".join(f'printf "%s\\0" "${{V{i}}}"\n' for i in range(len(HOSTILE)))
        + f"[ -e {marker} ] && echo EXECUTED >&2\n"
        + '[ -z "${PWNED+x}" ] || echo PWNED >&2\n'
    )
    # make the $(touch ...) payload point at the marker so an execution would be visible
    code = code.replace("/tmp/pwned", str(marker))
    proc = subprocess.run([shell, "-c", script, "sh", code], capture_output=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == b""
    produced = proc.stdout.split(b"\0")[:-1]
    expected = [v.replace("/tmp/pwned", str(marker)).encode() for v in HOSTILE]
    assert produced == expected
    assert not marker.exists()


def test_format_dotenv():
    assert format_dotenv({"A": "plain-value_1.2/x:y@z%+,=", "B": "two words", "C": ""}) == (
        "A=plain-value_1.2/x:y@z%+,=\nB='two words'\nC=\n"
    )
    assert format_dotenv({"A": "a#b"}) == "A='a#b'\n"
    assert format_dotenv({"A": "$HOME"}) == "A='$HOME'\n"
    assert format_dotenv({"A": "it's"}) == 'A="it\'s"\n'
    assert format_dotenv({"A": 'q"\\\n$x'}) == 'A="q\\"\\\\\\n\\$x"\n'


def test_format_dotenv_validates_names():
    with pytest.raises(ValueError):
        format_dotenv({"1A": "x"})


def test_format_json():
    env = {"B": 'é\n"q"', "A": "1"}
    text = format_json(env)
    assert json.loads(text) == env
    assert list(json.loads(text)) == ["A", "B"]
    assert text.isascii() and text.endswith("\n")
    with pytest.raises(ValueError):
        format_json({"bad name": "x"})


def test_format_env_dispatch():
    env = {"A": "x y"}
    assert format_env(env, "shell") == "export A='x y'\n"
    assert format_env(env, "dotenv") == "A='x y'\n"
    assert json.loads(format_env(env, "json")) == env
    with pytest.raises(ValueError, match="unknown format"):
        format_env(env, "yaml")
