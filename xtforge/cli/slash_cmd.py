"""Slash-command CLI handler: same grammar as the MCP and plugin paths."""
from __future__ import annotations

from .common import _out, _flash, _store


def cmd_slash(args):
    from ..core.slash import dispatch, reply_text
    text = " ".join(args.text).strip()
    st = _store(args)
    try:
        res = dispatch(text, flash=_flash(args), store=st)
    finally:
        st.close()
    return _out(args, res, reply_text(res), code=0 if res.get("ok") else 1)
