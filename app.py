import os
from flask import Flask, request, redirect, render_template_string, abort
import stripe
import requests
from dotenv import load_dotenv

# ------------ Load environment variables ------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")

# ------------ Stripe config ------------
stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
STRIPE_WEBHOOK_SECRET = os.environ["STRIPE_WEBHOOK_SECRET"]

# These come from env vars you will set in Render
PLAN_LABEL = os.environ.get("PLAN_LABEL", "EventLink Day Pass")
PLAN_PRICE_ID = os.environ["PLAN_PRICE_ID"]   # e.g. price_123 from Stripe
PLAN_DURATION_SECS = int(os.environ.get("PLAN_DURATION_SECS", "86400"))  # default 24h

SUCCESS_URL = os.environ["SUCCESS_URL"]
CANCEL_URL = os.environ["CANCEL_URL"]

# ------------ Omada (OC200) config ------------
OMADA_BASE_URL = os.environ["OMADA_BASE_URL"]      # e.g. https://192.168.0.103
OMADA_USERNAME = os.environ["OMADA_USERNAME"]
OMADA_PASSWORD = os.environ["OMADA_PASSWORD"]
OMADA_VERIFY_SSL = os.getenv("OMADA_VERIFY_SSL", "false").lower() == "true"

http_session = requests.Session()
http_session.verify = OMADA_VERIFY_SSL


# ------------ Omada helpers ------------

def omada_login():
    """
    Log in to the Omada controller (OC200).
    """
    payload = {
        "username": OMADA_USERNAME,
        "password": OMADA_PASSWORD,
    }
    r = http_session.post(f"{OMADA_BASE_URL}/login", json=payload)
    r.raise_for_status()


def omada_authorize_client(site, cid, ap, ssid, rid, t_value, duration_secs):
    """
    Tell Omada to authorize this client (MAC) for a certain time.
    """
    omada_login()

    auth_payload = {
        "cid": cid,
        "ap": ap,
        "ssid": ssid,
        "rid": rid,
        "t": t_value,
        "site": site,
        "time": duration_secs,
    }

    r = http_session.post(
        f"{OMADA_BASE_URL}/extportal/{site}/auth",
        json=auth_payload
    )
    r.raise_for_status()
    data = r.json()
    if not data.get("success", False):
        raise RuntimeError(f"Omada auth failed: {data}")


# ------------ Routes ------------

@app.route("/")
def health():
    return "OK", 200


@app.get("/portal")
def portal_entry():
    """
    Called by Omada when a user connects and hits the captive portal.
    """
    cid = request.args.get("cid")      # client MAC
    ap = request.args.get("ap")        # AP MAC
    ssid = request.args.get("ssid")
    t_param = request.args.get("t")
    rid = request.args.get("rid")
    site = request.args.get("site")
    system_key = request.args.get("system_id", "KIT-M1")  # default KIT-M1

    if not all([cid, ap, ssid, t_param, rid, site]):
        return "Missing required parameters", 400

    html = """
    <html>
      <head><title>EventLink WiFi</title></head>
      <body>
        <h1>EventLink WiFi – Mobile Kit 1</h1>
        <p>Select a pass to get online:</p>

        <form action="/create-checkout-session" method="POST">
          <input type="hidden" name="cid" value="{{ cid }}">
          <input type="hidden" name="ap" value="{{ ap }}">
          <input type="hidden" name="ssid" value="{{ ssid }}">
          <input type="hidden" name="t_param" value="{{ t_param }}">
          <input type="hidden" name="rid" value="{{ rid }}">
          <input type="hidden" name="site" value="{{ site }}">

          <button type="submit" style="padding:0.75rem 1.5rem; font-size:1rem;">
            {{ plan_label }}
          </button>
        </form>

        <p style="margin-top:1rem; font-size:0.9rem; color:#666;">
          Powered by EventLink Mobile Kit 1
        </p>
      </body>
    </html>
    """
    return render_template_string(
        html,
        cid=cid,
        ap=ap,
        ssid=ssid,
        t_param=t_param,
        rid=rid,
        site=site,
        plan_label=PLAN_LABEL,
    )


@app.post("/create-checkout-session")
def create_checkout_session():
    """
    Called when user clicks the button on the portal.
    Creates Stripe checkout session.
    """
    cid = request.form["cid"]
    ap = request.form["ap"]
    ssid = request.form["ssid"]
    t_param = request.form["t_param"]
    rid = request.form["rid"]
    site = request.form["site"]

    checkout_session = stripe.checkout.Session.create(
        mode="payment",
        line_items=[{"price": PLAN_PRICE_ID, "quantity": 1}],
        success_url=SUCCESS_URL + "?session_id={CHECKOUT_SESSION_ID}",
        cancel_url=CANCEL_URL,
        metadata={
            "client_mac": cid,
            "ap_mac": ap,
            "ssid": ssid,
            "t_param": t_param,
            "rid": rid,
            "site": site,
            "plan_label": PLAN_LABEL,
        },
    )

    return redirect(checkout_session.url, code=303)


@app.post("/stripe/webhook")
def stripe_webhook():
    """
    Stripe calls this when payment is successful.
    We then authorize the device in Omada.
    """
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=STRIPE_WEBHOOK_SECRET
        )
    except Exception:
        return "Invalid payload", 400

    if event["type"] == "checkout.session.completed":
        sess = event["data"]["object"]
        md = sess.get("metadata", {})

        cid = md.get("client_mac")
        ap = md.get("ap_mac")
        ssid = md.get("ssid")
        t_param = md.get("t_param")
        rid = md.get("rid")
        site = md.get("site")

        omada_authorize_client(
            site=site,
            cid=cid,
            ap=ap,
            ssid=ssid,
            rid=rid,
            t_value=t_param,
            duration_secs=PLAN_DURATION_SECS,
        )

    return "OK", 200


@app.get("/success")
def success_page():
    return """
    <html>
      <head><title>EventLink WiFi</title></head>
      <body>
        <h1>You’re Online!</h1>
        <p>Your payment was successful. Enjoy your access.</p>
        <p>If it doesn’t work immediately, toggle WiFi off/on.</p>
      </body>
    </html>
    """


@app.get("/cancel")
def cancel_page():
    return """
    <html>
      <head><title>EventLink WiFi</title></head>
      <body>
        <h1>Payment cancelled</h1>
        <p>No charge was made. Close this page or try again.</p>
      </body>
    </html>
    """


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
