import csv
import io
import os

import markdown
from flask import Flask, render_template, request
from markupsafe import Markup
from detector import detect_threat
from ai_analyst import analyse_threat

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB upload limit

# Each Gemini call takes a few seconds, so only analyse the first few threats.
MAX_AI_REPORTS = 3

# Markdown features we don't allow in AI output. Gemini's text is influenced by
# the uploaded log, so raw HTML or links could be used to inject content.
UNSAFE_MARKDOWN = {
    "inlinePatterns": [
        "html", "link", "reference", "short_reference", "autolink",
        "automail", "image_link", "image_reference", "short_image_ref",
    ],
    "preprocessors": ["html_block"],
}


def render_markdown(text):
    """Convert Gemini's markdown to HTML with raw HTML and links disabled."""
    md = markdown.Markdown(extensions=["sane_lists"])

    for registry, names in UNSAFE_MARKDOWN.items():
        for name in names:
            if name in getattr(md, registry):
                getattr(md, registry).deregister(name)

    return Markup(md.convert(text or ""))


REQUIRED_COLUMNS = {"event_type", "username", "ip_address"}


def parse_csv(file_storage):
    """Turn an uploaded CSV into a list of event dicts.

    Raises ValueError if the file is empty or missing required columns.
    """
    text = file_storage.read().decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))

    # Normalise headers like " Event_Type " -> "event_type".
    headers = {(name or "").strip().lower() for name in reader.fieldnames or []}
    missing = REQUIRED_COLUMNS - headers
    if missing:
        raise ValueError(
            "CSV is missing required columns: " + ", ".join(sorted(missing))
        )

    events = []
    for row in reader:
        events.append({
            key.strip().lower(): (value or "").strip()
            for key, value in row.items()
            # Rows with extra values put them under a None key; ignore those.
            if key is not None
        })

    return events


@app.route("/")
def dashboard():
    return render_template("index.html", threats=[], event_count=0)


@app.route("/analyze", methods=["POST"])
def analyze():
    upload = request.files.get("file")

    if not upload or not upload.filename.lower().endswith(".csv"):
        return render_template(
            "index.html",
            threats=[],
            event_count=0,
            error="Please upload a .csv file.",
        )

    try:
        events = parse_csv(upload)
    except csv.Error as e:
        return render_template(
            "index.html",
            threats=[],
            event_count=0,
            error=f"Could not read CSV: {e}",
        )
    except ValueError as e:
        return render_template(
            "index.html",
            threats=[],
            event_count=0,
            error=str(e),
        )

    threats = detect_threat(events)

    for threat in threats[:MAX_AI_REPORTS]:
        threat["ai_analysis"] = render_markdown(analyse_threat(threat))

    return render_template(
        "index.html",
        threats=threats,
        event_count=len(events),
        filename=upload.filename,
    )


@app.errorhandler(413)
def file_too_large(_error):
    return render_template(
        "index.html",
        threats=[],
        event_count=0,
        error="File is too large. The maximum upload size is 5 MB.",
    ), 413


if __name__ == "__main__":
    # Debug mode is only for local development. Enable it with FLASK_DEBUG=1.
    app.run(debug=os.getenv("FLASK_DEBUG") == "1")
