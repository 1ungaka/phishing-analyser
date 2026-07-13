from flask import Flask, render_template, request, jsonify
from core.parser import parse_email
from core.scorer import calculate_threat_score
from core.vt_checker import check_urls_batch

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyse", methods=["POST"])
def analyse():
    if "email_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["email_file"]
    if not file.filename.endswith(".eml"):
        return jsonify({"error": "Only .eml files are supported"}), 400

    file_bytes = file.read()

    try:
        parsed = parse_email(file_bytes)
    except Exception as e:
        return jsonify({"error": f"Failed to parse email: {str(e)}"}), 500

    check_vt = request.form.get("check_vt") == "true"
    vt_results = {}

    if check_vt and parsed["links"]:
        vt_results = check_urls_batch(parsed["links"], max_checks=5)
        for link in parsed["links"]:
            if link["url"] in vt_results:
                link["vt_result"] = vt_results[link["url"]]

    threat = calculate_threat_score(parsed, vt_results)

    return jsonify({
        "headers": parsed["headers"],
        "links": parsed["links"],
        "attachments": parsed["attachments"],
        "body_preview": parsed["body_preview"],
        "keywords_found": parsed["keywords_found"],
        "spoofing": parsed["spoofing"],
        "threat": threat,
    })


if __name__ == "__main__":
    app.run(debug=True)
