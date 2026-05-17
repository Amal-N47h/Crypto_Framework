from crypto_vimal.result_classifier import verify_packet
from flask import Flask, render_template, request, jsonify
import uuid


app = Flask(__name__)

# store results in memory (for dashboard)
results = []


@app.route("/")
def index():
    return render_template("dashboard.html", results=results)


@app.route("/verify", methods=["POST"])
def verify():
    try:
        packet = request.json

        # assign packet id
        packet_id = str(uuid.uuid4())

        result = verify_packet(packet)
        result.packet_id = packet_id

        # store
        results.insert(0, result)

        return jsonify({
            "packet_id": packet_id,
            "status": result.status.value,
            "reason": result.reason
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 400


if __name__ == "__main__":
    app.run(debug=True)