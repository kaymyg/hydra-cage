"""Hugging Face Space front end for the Hydra Cage.

Thin wrapper. All the plumbing lives in runner.py so it can be tested without
a Gradio install; everything below is layout.
"""

from __future__ import annotations

import gradio as gr

import runner

INTRO = """
# The Hydra Cage

**Disposable trust and regenerative containment for autonomous AI.**

When a containment layer is breached, Hydra does not patch it. It freezes the
domain, cuts its interconnects, seals it as immutable forensic evidence,
permanently revokes its cryptographic identity, and builds a fresh layer
*outside* the attacker's position. The breached layer becomes a deeper cell.
The outside recedes faster than the attacker advances.

Everything below runs live, in this Space, right now.

> Spaces cannot nest containers, so this runs the **process backend** — one
> process group per layer, `SIGSTOP` for freeze, `/proc` as the observation
> root. The Docker backend in the repo does the same thing with real
> containers, own network per layer, `--cap-drop ALL`, and `docker export` for
> forensics. Identical trust topology either way, which is the part worth
> watching.
"""

DEMO_BLURB = """
Five acts: boot the five planes, run a workload, watch a layer modify itself
and lie about it, then watch effective depth climb across repeated breaches.
Takes about a minute.
"""

ATTACK_BLURB = """
Ten escape attempts, each naming the control meant to stop it. The harness
records which one actually did. Watch for `perfect_liar` — a byte-perfect
forgery of a healthy heartbeat that fails anyway, because the sentinel never
asked the domain what its measurement was.
"""

CSS = """
#transcript textarea, #transcript code {
    font-family: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, monospace;
    font-size: 12px;
    line-height: 1.45;
}
"""


def build() -> gr.Blocks:
    with gr.Blocks(title="The Hydra Cage", css=CSS, theme=gr.themes.Soft()) as app:
        gr.Markdown(INTRO)

        with gr.Row():
            layers = gr.Slider(
                minimum=2,
                maximum=runner.MAX_LAYERS,
                value=4,
                step=1,
                label="Nested containment layers",
            )

        with gr.Tabs():
            with gr.Tab("Full demonstration"):
                gr.Markdown(DEMO_BLURB)
                demo_btn = gr.Button("Run the demo", variant="primary")
                demo_out = gr.Textbox(
                    label="transcript",
                    lines=32,
                    max_lines=32,
                    show_copy_button=True,
                    elem_id="transcript",
                    autoscroll=True,
                )
                demo_btn.click(
                    fn=lambda n: (yield from runner.stream("demo", n)),
                    inputs=layers,
                    outputs=demo_out,
                )

            with gr.Tab("Adversary suite"):
                gr.Markdown(ATTACK_BLURB)
                atk_btn = gr.Button("Run ten escape attempts", variant="primary")
                atk_out = gr.Textbox(
                    label="transcript",
                    lines=32,
                    max_lines=32,
                    show_copy_button=True,
                    elem_id="transcript",
                    autoscroll=True,
                )
                atk_btn.click(
                    fn=lambda n: (yield from runner.stream("attack", n)),
                    inputs=layers,
                    outputs=atk_out,
                )

            with gr.Tab("Force a breach"):
                gr.Markdown(
                    "Trigger one breach transition directly and watch all eight "
                    "stages with their timings: detect, freeze, sever, preserve, "
                    "revoke, rebuild, reattest, reinsert."
                )
                br_btn = gr.Button("Force a breach transition", variant="primary")
                br_out = gr.Textbox(
                    label="transcript",
                    lines=32,
                    max_lines=32,
                    show_copy_button=True,
                    elem_id="transcript",
                    autoscroll=True,
                )
                br_btn.click(
                    fn=lambda n: (yield from runner.stream("breach", n)),
                    inputs=layers,
                    outputs=br_out,
                )

        gr.Markdown(
            "---\n"
            "**Honest limits.** This raises the cost of escape and guarantees "
            "forensic evidence; it is not a mathematical guarantee of "
            "containment. Nested enclaves share microcode, a TEE, a management "
            "controller, and a supply chain — a flaw in any of them defeats "
            "every layer at once. Side channels cross logical boundaries. "
            "Detection is periodic, so a breach is caught on the next sweep, "
            "not instantly. And none of it addresses a model that achieves its "
            "goals through the outputs it was legitimately asked to produce.\n\n"
            "Source, tests, and the Docker backend: "
            "[github.com/kaymyg/hydra-cage](https://github.com/kaymyg/hydra-cage) · "
            "Apache-2.0"
        )
    return app


if __name__ == "__main__":
    build().queue(max_size=8).launch(server_name="0.0.0.0", server_port=7860)
